//
//  DeviceDataManager.swift
//  SideSign
//
//  Created by Magesh K on 01/09/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
import Crypto
import GSACryptoKit
import SideSign

public enum DeviceDataError: LocalizedError, Sendable {
    case fileNotFound(URL)
    case corruptedData
    case invalidPassword
    case encryptionFailed(String)
    case decryptionFailed(String)

    public var errorDescription: String? {
        switch self {
        case .fileNotFound(let url):
            return "Device data file not found at '\(url.path)'."
        case .corruptedData:
            return "Device data file is corrupted or in an unrecognized format."
        case .invalidPassword:
            return "Failed to decrypt device data: invalid password."
        case .encryptionFailed(let reason):
            return "Device data encryption failed: \(reason)"
        case .decryptionFailed(let reason):
            return "Device data decryption failed: \(reason)"
        }
    }
}

public struct DeviceDataManager: Sendable {

    public static var defaultDirectory: URL {
        return SessionManager.defaultSessionDirectory
    }

    public static var defaultURL: URL {
        return defaultDirectory.appendingPathComponent(Constants.DeviceData.defaultFileName)
    }

    public static func hasData(at url: URL? = nil) -> Bool {
        let targetURL = url ?? defaultURL
        return FileManager.default.fileExists(atPath: targetURL.path)
    }

    public static func save(
        _ deviceData: DeviceData,
        to destinationURL: URL? = nil,
        password: String
    ) throws {
        let targetURL = destinationURL ?? defaultURL
        let dirURL = targetURL.deletingLastPathComponent()

        if !FileManager.default.fileExists(atPath: dirURL.path) {
            try FileManager.default.createDirectory(at: dirURL, withIntermediateDirectories: true)
        }

        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        let plaintextData = try encoder.encode(deviceData)

        var saltData = Data(count: Constants.Session.saltLength)
        let saltResult = saltData.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, Constants.Session.saltLength, $0.baseAddress!) }
        if saltResult != errSecSuccess {
            saltData = Data((0..<Constants.Session.saltLength).map { _ in UInt8.random(in: 0...255) })
        }

        let symmetricKey = try deriveKey(from: password, salt: saltData)
        let sealedBox = try AES.GCM.seal(plaintextData, using: symmetricKey)

        var filePayload = Data(Constants.DeviceData.magic)
        filePayload.append(saltData)
        filePayload.append(Data(sealedBox.nonce))
        filePayload.append(sealedBox.tag)
        filePayload.append(sealedBox.ciphertext)

        try filePayload.write(to: targetURL, options: .atomic)

        #if !os(Windows)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: targetURL.path)
        #endif
    }

    public static func load(
        from sourceURL: URL? = nil,
        password: String
    ) throws -> DeviceData {
        let targetURL = sourceURL ?? defaultURL

        guard FileManager.default.fileExists(atPath: targetURL.path) else {
            throw DeviceDataError.fileNotFound(targetURL)
        }

        let fileData = try Data(contentsOf: targetURL)

        let magicLen = Constants.DeviceData.magic.count
        let saltLen = Constants.Session.saltLength
        let nonceLen = Constants.Session.nonceLength
        let tagLen = Constants.Session.tagLength
        let minExpected = magicLen + saltLen + nonceLen + tagLen

        guard fileData.count >= minExpected else {
            throw DeviceDataError.corruptedData
        }

        let magic = [UInt8](fileData.prefix(magicLen))
        guard magic == Constants.DeviceData.magic else {
            throw DeviceDataError.corruptedData
        }

        var offset = magicLen
        let saltData = fileData.subdata(in: offset..<(offset + saltLen))
        offset += saltLen
        let nonceBytes = fileData.subdata(in: offset..<(offset + nonceLen))
        offset += nonceLen
        let tagBytes = fileData.subdata(in: offset..<(offset + tagLen))
        offset += tagLen
        let ciphertext = fileData.subdata(in: offset..<fileData.count)

        let symmetricKey = try deriveKey(from: password, salt: saltData)
        let nonce = try AES.GCM.Nonce(data: nonceBytes)
        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tagBytes)

        let decryptedData: Data
        do {
            decryptedData = try AES.GCM.open(sealedBox, using: symmetricKey)
        } catch {
            throw DeviceDataError.invalidPassword
        }

        let decoder = PropertyListDecoder()
        do {
            return try decoder.decode(DeviceData.self, from: decryptedData)
        } catch {
            throw DeviceDataError.corruptedData
        }
    }

    public static func clear(at url: URL? = nil) throws {
        let targetURL = url ?? defaultURL
        if FileManager.default.fileExists(atPath: targetURL.path) {
            try FileManager.default.removeItem(at: targetURL)
        }
    }

    private static func deriveKey(from password: String, salt: Data) throws -> SymmetricKey {
        guard let passwordData = password.data(using: .utf8),
              let derived = CryptoUtilities.pbkdf2SHA256(
                password: passwordData,
                salt: salt,
                rounds: Constants.Session.pbkdf2Rounds,
                outputLength: Constants.Session.keyOutputLength
              ) else {
            throw DeviceDataError.encryptionFailed("Failed to derive encryption key from password.")
        }

        return SymmetricKey(data: derived)
    }
}
