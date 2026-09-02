//
//  SessionManager.swift
//  SideSign
//
//  Created by Magesh K on 31/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
import Crypto
import GSACryptoKit
import SideSign

public enum SessionStorageError: LocalizedError, Sendable {
    case fileNotFound(URL)
    case corruptedData
    case invalidPassword
    case encryptionFailed(String)
    case decryptionFailed(String)

    public var errorDescription: String? {
        switch self {
        case .fileNotFound(let url):
            return "Session file not found at '\(url.path)'."
        case .corruptedData:
            return "Session file is corrupted or in an unrecognized format."
        case .invalidPassword:
            return "Failed to decrypt session: invalid password."
        case .encryptionFailed(let reason):
            return "Session encryption failed: \(reason)"
        case .decryptionFailed(let reason):
            return "Session decryption failed: \(reason)"
        }
    }
}
public struct SessionManager: Sendable {

    public static var defaultSessionDirectory: URL {
        let env = ProcessInfo.processInfo.environment

        if let xdgConfig = env[Constants.Session.envXDGConfig], !xdgConfig.isEmpty {
            return URL(fileURLWithPath: xdgConfig).appendingPathComponent(Constants.Session.defaultDirName)
        }

        if let appData = env[Constants.Session.envAppData], !appData.isEmpty {
            return URL(fileURLWithPath: appData).appendingPathComponent(Constants.Session.defaultDirName)
        }

        let homeDir: String
        if let home = env[Constants.Session.envHome], !home.isEmpty {
            homeDir = home
        } else {
            homeDir = NSHomeDirectory()
        }

        return URL(fileURLWithPath: homeDir)
            .appendingPathComponent(".config")
            .appendingPathComponent(Constants.Session.defaultDirName)
    }

    public static var defaultSessionURL: URL {
        return defaultSessionDirectory.appendingPathComponent(Constants.Session.defaultFileName)
    }

    public static func hasSession(at url: URL? = nil) -> Bool {
        let targetURL = url ?? defaultSessionURL
        return FileManager.default.fileExists(atPath: targetURL.path)
    }

    public static func save(
        _ authSession: AuthSession,
        to destinationURL: URL? = nil,
        password: String? = nil
    ) throws {
        let targetURL = destinationURL ?? defaultSessionURL
        let dirURL = targetURL.deletingLastPathComponent()

        if !FileManager.default.fileExists(atPath: dirURL.path) {
            try FileManager.default.createDirectory(at: dirURL, withIntermediateDirectories: true)
        }

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let plainData = try encoder.encode(authSession)

        let isPasswordMode = (password != nil && !password!.isEmpty)
        let magic = isPasswordMode ? Constants.Session.passMagic : Constants.Session.autoMagic

        let salt = Data((0..<Constants.Session.saltLength).map { _ in UInt8.random(in: 0...255) })

        let symmetricKey: SymmetricKey
        if let pwd = password, !pwd.isEmpty {
            guard let pwdData = pwd.data(using: .utf8),
                  let derived = CryptoUtilities.pbkdf2SHA256(
                    password: pwdData,
                    salt: salt,
                    rounds: Constants.Session.pbkdf2Rounds,
                    outputLength: Constants.Session.keyOutputLength
                  ) else {
                throw SessionStorageError.encryptionFailed("Failed to derive encryption key from password.")
            }
            symmetricKey = SymmetricKey(data: derived)
        } else {
            symmetricKey = deriveMachineKey(salt: salt)
        }

        let sealedBox: AES.GCM.SealedBox
        do {
            sealedBox = try AES.GCM.seal(plainData, using: symmetricKey)
        } catch {
            throw SessionStorageError.encryptionFailed(error.localizedDescription)
        }

        var outputData = Data()
        outputData.append(contentsOf: magic)
        outputData.append(salt)
        outputData.append(Data(sealedBox.nonce))
        outputData.append(sealedBox.tag)
        outputData.append(sealedBox.ciphertext)

        try outputData.write(to: targetURL, options: .atomic)

        #if !os(Windows)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: targetURL.path)
        #endif
    }

    public static func load(
        from sourceURL: URL? = nil,
        password: String? = nil
    ) throws -> AuthSession {
        let targetURL = sourceURL ?? defaultSessionURL

        guard FileManager.default.fileExists(atPath: targetURL.path) else {
            throw SessionStorageError.fileNotFound(targetURL)
        }

        let fileData = try Data(contentsOf: targetURL)
        let headerSize = 4 + Constants.Session.saltLength + Constants.Session.nonceLength + Constants.Session.tagLength

        guard fileData.count > headerSize else {
            throw SessionStorageError.corruptedData
        }

        let magic = Array(fileData[0..<4])
        let salt = fileData.subdata(in: 4..<4 + Constants.Session.saltLength)
        let nonceData = fileData.subdata(in: 4 + Constants.Session.saltLength..<4 + Constants.Session.saltLength + Constants.Session.nonceLength)
        let tag = fileData.subdata(in: 4 + Constants.Session.saltLength + Constants.Session.nonceLength..<headerSize)
        let ciphertext = fileData.subdata(in: headerSize..<fileData.count)

        let symmetricKey: SymmetricKey

        if magic == Constants.Session.passMagic {
            guard let pwd = password, !pwd.isEmpty else {
                throw SessionStorageError.invalidPassword
            }
            guard let pwdData = pwd.data(using: .utf8),
                  let derived = CryptoUtilities.pbkdf2SHA256(
                    password: pwdData,
                    salt: salt,
                    rounds: Constants.Session.pbkdf2Rounds,
                    outputLength: Constants.Session.keyOutputLength
                  ) else {
                throw SessionStorageError.decryptionFailed("Failed to derive decryption key from password.")
            }
            symmetricKey = SymmetricKey(data: derived)
        } else if magic == Constants.Session.autoMagic {
            symmetricKey = deriveMachineKey(salt: salt)
        } else {
            throw SessionStorageError.corruptedData
        }

        let nonce: AES.GCM.Nonce
        do {
            nonce = try AES.GCM.Nonce(data: nonceData)
        } catch {
            throw SessionStorageError.corruptedData
        }

        guard let sealedBox = try? AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag) else {
            throw SessionStorageError.corruptedData
        }

        let decryptedData: Data
        do {
            decryptedData = try AES.GCM.open(sealedBox, using: symmetricKey)
        } catch {
            if magic == Constants.Session.passMagic {
                throw SessionStorageError.invalidPassword
            } else {
                throw SessionStorageError.decryptionFailed("Decryption failed. Machine credentials or session file may have changed.")
            }
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        do {
            return try decoder.decode(AuthSession.self, from: decryptedData)
        } catch {
            throw SessionStorageError.corruptedData
        }
    }

    public static func clear(at url: URL? = nil) throws {
        let targetURL = url ?? defaultSessionURL
        if FileManager.default.fileExists(atPath: targetURL.path) {
            try FileManager.default.removeItem(at: targetURL)
        }
    }

    private static func deriveMachineKey(salt: Data) -> SymmetricKey {
        let env = ProcessInfo.processInfo.environment
        let username = env[Constants.Session.envUser] ?? env[Constants.Session.envUsername] ?? NSUserName()
        let hostname = ProcessInfo.processInfo.hostName

        var machineSeed = "\(username):\(hostname):\(Constants.Session.machineSeedDomain)"

        #if os(Linux)
        if let machineID = try? String(contentsOfFile: "/etc/machine-id", encoding: .utf8) {
            machineSeed += ":\(machineID.trimmingCharacters(in: .whitespacesAndNewlines))"
        }
        #endif

        let ikmData = machineSeed.data(using: .utf8) ?? Data(Constants.Session.fallbackSeed.utf8)
        let ikm = SymmetricKey(data: ikmData)

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: ikm,
            salt: salt,
            info: Data(Constants.Session.machineSeedInfo.utf8),
            outputByteCount: Constants.Session.keyOutputLength
        )
    }
}


