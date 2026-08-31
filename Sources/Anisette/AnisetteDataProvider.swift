//
//  AnisetteDataProvider.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
import Crypto
import AnisetteKit

extension LocalAnisetteProvider: @retroactive @unchecked Sendable {}

public enum AnisetteMode: Sendable, Equatable, Codable, Hashable {
    case remote(server: URL)
    case localODA(libsDir: URL, provisioningDir: URL? = nil)
    case remoteODA(sourceURL: URL, fallbackURL: URL? = nil)
}

public struct ODAInfo: Codable, Equatable, Sendable {
    public let url: String?
    public let base64Payload: String?
    public let sha256: String?

    enum CodingKeys: String, CodingKey {
        case url
        case sha256
        case sha
        case s
        case l
        case payload
        case data
        case libraries
    }

    public init(url: String? = nil, base64Payload: String? = nil, sha256: String? = nil) {
        self.url = url
        self.base64Payload = base64Payload
        self.sha256 = sha256
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let decodedSha = (try? container.decodeIfPresent(String.self, forKey: .sha256))
            ?? (try? container.decodeIfPresent(String.self, forKey: .sha))
            ?? (try? container.decodeIfPresent(String.self, forKey: .s))
        self.sha256 = decodedSha

        var decodedL: String? = try? container.decodeIfPresent(String.self, forKey: .l)
        if decodedL == nil { decodedL = try? container.decodeIfPresent(String.self, forKey: .libraries) }
        if decodedL == nil { decodedL = try? container.decodeIfPresent(String.self, forKey: .payload) }
        if decodedL == nil { decodedL = try? container.decodeIfPresent(String.self, forKey: .data) }
        let lVal = decodedL
        let urlVal = try? container.decodeIfPresent(String.self, forKey: .url)

        if let raw = lVal ?? urlVal {
            if raw.hasPrefix("http://") || raw.hasPrefix("https://") {
                self.url = raw
                self.base64Payload = nil
            } else {
                self.url = nil
                self.base64Payload = raw
            }
        } else {
            self.url = nil
            self.base64Payload = nil
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(url, forKey: .url)
        try container.encodeIfPresent(base64Payload, forKey: .l)
        try container.encodeIfPresent(sha256, forKey: .s)
    }
}

public enum ODAValue: Codable, Equatable, Sendable {
    case path(String)
    case direct(ODAInfo)

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let stringVal = try? container.decode(String.self) {
            self = .path(stringVal)
        } else if let info = try? container.decode(ODAInfo.self) {
            self = .direct(info)
        } else {
            throw DecodingError.typeMismatch(
                ODAValue.self,
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Expected String or ODAInfo dictionary for 'oda'"
                )
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .path(let path):
            try container.encode(path)
        case .direct(let info):
            try container.encode(info)
        }
    }
}

public struct AnisetteServerItem: Codable, Identifiable, Hashable, Sendable {
    public var id: String { address }
    public var name: String
    public var address: String
    public var isHidden: Bool

    enum CodingKeys: String, CodingKey {
        case name
        case address
        case url
        case isHidden
    }

    public init(name: String, address: String, isHidden: Bool = false) {
        self.name = name
        self.address = address
        self.isHidden = isHidden
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.name = (try? container.decode(String.self, forKey: .name)) ?? ""
        self.address = (try? container.decode(String.self, forKey: .address))
            ?? (try? container.decode(String.self, forKey: .url)) ?? ""
        self.isHidden = (try? container.decode(Bool.self, forKey: .isHidden)) ?? false
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(name, forKey: .name)
        try container.encode(address, forKey: .address)
        try container.encode(isHidden, forKey: .isHidden)
    }
}

public struct AnisetteServerData: Codable, Sendable {
    public let servers: [AnisetteServerItem]
    public let oda: ODAValue?

    enum CodingKeys: String, CodingKey {
        case servers
        case oda
    }

    public init(servers: [AnisetteServerItem], oda: ODAValue? = nil) {
        self.servers = servers
        self.oda = oda
    }

    public init(from decoder: Decoder) throws {
        if let container = try? decoder.container(keyedBy: CodingKeys.self) {
            self.servers = (try? container.decode([AnisetteServerItem].self, forKey: .servers)) ?? []
            self.oda = try? container.decodeIfPresent(ODAValue.self, forKey: .oda)
        } else if let array = try? decoder.singleValueContainer().decode([AnisetteServerItem].self) {
            self.servers = array
            self.oda = nil
        } else {
            self.servers = []
            self.oda = nil
        }
    }
}

public enum AnisetteError: LocalizedError, Sendable {
    case modeNotConfigured
    case invalidServerSourceURL
    case missingODAEntry
    case downloadFailed(String)
    case sha256Mismatch(expected: String, actual: String)
    case invalidBase64Payload
    case decompressionFailed(String)
    case missingRequiredLibs([String])
    case appGroupContainerNotFound
    case providerNotReady(String)
    case invalidAnisetteData
    case badServerResponse(statusCode: Int, payload: String)
    case noServersConfigured
    case allServersFailed
    case invalidURL
    case outdatedV1Server(server: URL, reason: String? = nil)
    case serverListFetchFailed(String)

    public var errorDescription: String? {
        switch self {
        case .modeNotConfigured:
            return "No Anisette operating mode is configured. Set activeMode or pass a mode parameter."
        case .invalidServerSourceURL:
            return "Invalid Anisette server list source URL."
        case .invalidURL:
            return "Invalid URL provided for Anisette endpoint."
        case .missingODAEntry:
            return "No 'oda' configuration found in Anisette servers JSON."
        case .downloadFailed(let reason):
            return "Failed to download On-Device Anisette package: \(reason)"
        case .sha256Mismatch(let expected, let actual):
            return "SHA-256 checksum mismatch for On-Device Anisette package (expected \(expected), got \(actual))."
        case .invalidBase64Payload:
            return "Downloaded On-Device Anisette payload is not valid Base64 data."
        case .decompressionFailed(let reason):
            return "Failed to decompress On-Device Anisette archive: \(reason)"
        case .missingRequiredLibs(let names):
            return "Required ADI shared libraries (\(names.joined(separator: ", "))) were not found in the extracted archive."
        case .appGroupContainerNotFound:
            return "Shared App Group container URL could not be resolved."
        case .providerNotReady(let reason):
            return "Local Anisette provider is not ready: \(reason)"
        case .invalidAnisetteData:
            return "Failed to construct valid AnisetteData from local or remote Anisette headers."
        case .badServerResponse(let statusCode, let payload):
            return "Anisette server returned HTTP status \(statusCode): \(payload)"
        case .noServersConfigured:
            return "No working anisette servers configured."
        case .allServersFailed:
            return "All configured Anisette servers failed to respond with valid Anisette data."
        case .outdatedV1Server(let url, let reason):
            if let reason = reason, !reason.isEmpty {
                return "V3 Anisette is unavailable on '\(url.absoluteString)' (\(reason)). Operating in legacy V1 mode (shared device identity)."
            } else {
                return "Anisette server '\(url.absoluteString)' is operating in outdated V1 mode (shared device identity)."
            }
        case .serverListFetchFailed(let reason):
            return "Failed to fetch server list: \(reason)"
        }
    }
}

public typealias OnDeviceAnisetteError = AnisetteError

public actor AnisetteDataProvider {
    public static let shared = AnisetteDataProvider()

    public static let hiddenBaseDirectoryName = ".anisette"
    public static let libsDirName = "Libraries"
    public static let provisioningDirName = "Provisioning"
    public static let appSupportSubdirectory = "SideStore"
    public static let defaultDeviceSerialNumber = "0"
    public static let iso8601DateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
    public static let posixLocaleIdentifier = "en_US_POSIX"
    public static let defaultTimeZoneAbbreviation = "UTC"
    public static let cachingPollingDelayNanoseconds: UInt64 = 200_000_000

    public var activeMode: AnisetteMode?
    public nonisolated let baseAnisetteDirectory: URL
    private var localProvider: LocalAnisetteProvider?
    private var isCaching: Bool = false

    public init(mode: AnisetteMode? = nil, baseDirectory: URL? = nil) {
        self.activeMode = mode
        if let base = baseDirectory {
            self.baseAnisetteDirectory = base
        } else {
            #if os(macOS)
            let homeDir = URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)
            self.baseAnisetteDirectory = homeDir.appendingPathComponent(Self.hiddenBaseDirectoryName, isDirectory: true)
            #elseif canImport(Darwin)
            if let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first {
                self.baseAnisetteDirectory = appSupport.appendingPathComponent(Self.hiddenBaseDirectoryName, isDirectory: true)
            } else {
                self.baseAnisetteDirectory = URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)
                    .appendingPathComponent(Self.hiddenBaseDirectoryName, isDirectory: true)
            }
            #else
            self.baseAnisetteDirectory = URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)
                .appendingPathComponent(Self.hiddenBaseDirectoryName, isDirectory: true)
            #endif
        }
    }

    public func setMode(_ mode: AnisetteMode) {
        self.activeMode = mode
    }

    public nonisolated var libsDir: URL {
        baseAnisetteDirectory.appendingPathComponent(Self.libsDirName, isDirectory: true)
    }

    public nonisolated var provisioningDir: URL {
        baseAnisetteDirectory.appendingPathComponent(Self.provisioningDirName, isDirectory: true)
    }

    public func isReady() -> Bool {
        LocalAnisetteProvider.validateLibrariesExist(at: libsDir)
    }

    public static func validateServer(url: URL, strict: Bool = false) async -> Bool {
        let v3URL = url.appendingPathComponent("v3").appendingPathComponent("client_info")
        var v3Req = URLRequest(url: v3URL)
        v3Req.timeoutInterval = 3
        v3Req.httpMethod = "GET"
        #if canImport(Darwin)
        v3Req.cachePolicy = .reloadIgnoringLocalCacheData
        #endif

        if let (data, response) = try? await URLSession.shared.data(for: v3Req),
           let httpResp = response as? HTTPURLResponse, (200...299).contains(httpResp.statusCode) {
            if !strict { return true }
            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               json["client_info"] != nil || json["user_agent"] != nil {
                return true
            }
        }

        var rootReq = URLRequest(url: url)
        rootReq.timeoutInterval = 3
        rootReq.httpMethod = "GET"
        #if canImport(Darwin)
        rootReq.cachePolicy = .reloadIgnoringLocalCacheData
        #endif

        if let (data, response) = try? await URLSession.shared.data(for: rootReq),
           let httpResp = response as? HTTPURLResponse, (200...299).contains(httpResp.statusCode) {
            if !strict { return true }
            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: String],
               (try? parseAnisetteData(from: json)) != nil {
                return true
            }
        }

        return false
    }

    public static func parseAnisetteData(
        from dictionary: [String: String],
        defaultDeviceID: String = UUID().uuidString,
        defaultClientInfo: String = LocalAnisetteProvider.defaultClientInfo,
        defaultLocalUserID: String = "0",
        defaultLocale: Locale = .current,
        defaultTimeZone: TimeZone = .current
    ) throws -> AnisetteData {
        var map = [String: String]()
        for (k, v) in dictionary {
            map[k.lowercased()] = v
        }

        guard
            let machineID = map["machineid"] ?? map["x-apple-i-md-m"],
            let otp = map["onetimepassword"] ?? map["x-apple-i-md"],
            let routingInfoString = map["routinginfo"] ?? map["x-apple-i-md-rinfo"],
            let routingInfo = UInt64(routingInfoString)
        else {
            throw AnisetteError.invalidAnisetteData
        }

        let localUserID = map["localuserid"] ?? map["x-apple-i-md-lu"] ?? defaultLocalUserID
        let serial = map["deviceserialnumber"] ?? map["x-apple-i-srl-no"] ?? "0"
        let deviceUID = map["deviceuniqueidentifier"] ?? map["x-mme-device-id"] ?? defaultDeviceID
        let desc = map["devicedescription"] ?? map["x-mme-client-info"] ?? defaultClientInfo

        let date: Date
        if let dateString = map["date"] ?? map["x-apple-i-client-time"] {
            if let isoDate = ISO8601DateFormatter().date(from: dateString) {
                date = isoDate
            } else {
                let df = DateFormatter()
                df.locale = Locale(identifier: "en_US_POSIX")
                df.dateFormat = "yyyy-MM-dd'T'HH:mm:ssZZZZZ"
                date = df.date(from: dateString) ?? Date()
            }
        } else {
            date = Date()
        }

        let locale: Locale
        if let localeID = map["locale"] ?? map["x-apple-locale"] {
            let cleanLocaleID = localeID.components(separatedBy: "@").first ?? localeID
            locale = Locale(identifier: cleanLocaleID)
        } else {
            locale = defaultLocale
        }

        let tz: TimeZone
        if let tzID = map["timezone"] ?? map["x-apple-i-timezone"] {
            tz = TimeZone(abbreviation: tzID) ?? TimeZone(identifier: tzID) ?? defaultTimeZone
        } else {
            tz = defaultTimeZone
        }

        return AnisetteData(
            machineID: machineID,
            oneTimePassword: otp,
            localUserID: localUserID,
            routingInfo: routingInfo,
            deviceUniqueIdentifier: deviceUID,
            deviceSerialNumber: serial,
            deviceDescription: desc,
            date: date,
            locale: locale,
            timeZone: tz
        )
    }

    public static func toHTTPHeaders(data: AnisetteData) -> [String: String] {
        let formatter = ISO8601DateFormatter()
        return [
            "X-Apple-I-MD-M": data.machineID,
            "X-Apple-I-MD": data.oneTimePassword,
            "X-Apple-I-MD-LU": data.localUserID,
            "X-Apple-I-MD-RINFO": String(data.routingInfo),
            "X-Mme-Device-Id": data.deviceUniqueIdentifier,
            "X-Apple-I-SRL-NO": data.deviceSerialNumber,
            "X-Mme-Client-Info": data.deviceDescription,
            "X-Apple-I-Client-Time": formatter.string(from: data.date),
            "X-Apple-Locale": data.locale.identifier.components(separatedBy: "@").first ?? "en_US",
            "X-Apple-I-TimeZone": data.timeZone.abbreviation() ?? "UTC"
        ]
    }

    public func fetchAnisetteData(
        mode: AnisetteMode? = nil,
        identifier: UUID = UUID(),
        existingAdiBlob: Data? = nil,
        clientInfo: String = LocalAnisetteProvider.defaultClientInfo,
        customLocalUserID: String? = nil,
        customDeviceID: String? = nil,
        customLocale: Locale = .current,
        customTimeZone: TimeZone = .current,
        onError: (@Sendable (Error) async throws -> Bool)? = nil
    ) async throws -> (data: AnisetteData, newAdiBlob: Data?) {
        guard let resolvedMode = mode ?? self.activeMode else {
            throw AnisetteError.modeNotConfigured
        }

        switch resolvedMode {
        case .remote(let server):
            let effectiveDeviceID = customDeviceID ?? identifier.uuidString
            var lastV3Error: Error?

            // 1. Try v3 get_headers with existing adi.pb if present
            if let adiBlob = existingAdiBlob {
                do {
                    debugLog("[Anisette] [v3] Fetching headers with existing adi.pb (\(adiBlob.count) bytes) from \(server.absoluteString)...")
                    let (data, _) = try await fetchV3Headers(server: server, identifier: effectiveDeviceID, adiBlob: adiBlob, clientInfo: clientInfo, customLocalUserID: customLocalUserID, customLocale: customLocale, customTimeZone: customTimeZone)
                    debugLog("[Anisette] [v3] Successfully acquired headers using existing adi.pb")
                    return (data, nil)
                } catch {
                    lastV3Error = error
                    debugLog("[Anisette] [v3] Existing adi.pb failed: \(error.localizedDescription)")
                }
            }

            // 2. Try remote v3 provisioning session
            var newlyProvisionedBlob: Data? = nil
            do {
                debugLog("[Anisette] [v3] Starting remote provisioning session with \(server.absoluteString)...")
                let remoteBlob = try await runRemoteProvisioningSession(server: server, identifier: identifier, clientInfo: clientInfo)
                newlyProvisionedBlob = remoteBlob
                debugLog("[Anisette] [v3] Provisioning successful! Fetching v3 headers with new adi.pb...")
                let (data, _) = try await fetchV3Headers(server: server, identifier: effectiveDeviceID, adiBlob: remoteBlob, clientInfo: clientInfo, customLocalUserID: customLocalUserID, customLocale: customLocale, customTimeZone: customTimeZone)
                debugLog("[Anisette] [v3] Successfully acquired headers using new adi.pb")
                return (data, newlyProvisionedBlob)
            } catch {
                lastV3Error = error
                debugLog("[Anisette] [v3] Remote provisioning failed: \(error.localizedDescription)")
            }

            // 3. Fallback to legacy v1 root GET
            debugLog("[Anisette] [v1] Falling back to legacy root GET on \(server.absoluteString)...")
            if let errorHandler = onError {
                let shouldContinue = try await errorHandler(AnisetteError.outdatedV1Server(server: server, reason: lastV3Error?.localizedDescription))
                guard shouldContinue else {
                    throw AnisetteError.outdatedV1Server(server: server, reason: lastV3Error?.localizedDescription)
                }
            }

            var request = URLRequest(url: server)
            request.cachePolicy = .reloadIgnoringLocalCacheData
            request.timeoutInterval = 15
            let (data, response) = try await URLSession.shared.data(for: request)

            guard let httpResp = response as? HTTPURLResponse, (200...299).contains(httpResp.statusCode) else {
                let status = (response as? HTTPURLResponse)?.statusCode ?? -1
                let payload = String(data: data, encoding: .utf8) ?? ""
                throw AnisetteError.badServerResponse(statusCode: status, payload: payload)
            }

            guard let json = try JSONSerialization.jsonObject(with: data) as? [String: String] else {
                throw AnisetteError.invalidAnisetteData
            }

            let anisette = try Self.parseAnisetteData(
                from: json,
                defaultDeviceID: effectiveDeviceID,
                defaultClientInfo: clientInfo,
                defaultLocale: customLocale,
                defaultTimeZone: customTimeZone
            )
            debugLog("[Anisette] [v1] Successfully acquired legacy v1 headers from \(server.absoluteString)")
            return (anisette, newlyProvisionedBlob)

        case .localODA(let libDir, let prov):
            let targetProvDir = prov ?? provisioningDir
            try FileManager.default.createDirectory(at: targetProvDir, withIntermediateDirectories: true)
            let provider = try LocalAnisetteProvider(
                provisioningDir: targetProvDir,
                clientInfo: clientInfo,
                libraryDirectoryResolver: { libDir }
            )

            let (headers, newAdiPb) = try await provider.getHeaders(identifier: identifier, storage: .memory(existingBlob: existingAdiBlob))
            guard let machineID = headers["X-Apple-I-MD-M"],
                  let oneTimePassword = headers["X-Apple-I-MD"],
                  let routingInfoStr = headers["X-Apple-I-MD-RINFO"],
                  let routingInfo = UInt64(routingInfoStr),
                  let localUserID = headers["X-Apple-I-MD-LU"] ?? customLocalUserID else {
                throw AnisetteError.invalidAnisetteData
            }

            let serial = headers["X-Apple-I-SRL-NO"] ?? "0"
            let deviceUID = customDeviceID ?? identifier.uuidString.uppercased()

            let anisetteData = AnisetteData(
                machineID: machineID,
                oneTimePassword: oneTimePassword,
                localUserID: localUserID,
                routingInfo: routingInfo,
                deviceUniqueIdentifier: deviceUID,
                deviceSerialNumber: serial,
                deviceDescription: clientInfo,
                date: Date(),
                locale: customLocale,
                timeZone: customTimeZone
            )
            return (anisetteData, newAdiPb)

        case .remoteODA(let sourceURL, let fallbackURL):
            try FileManager.default.createDirectory(at: libsDir, withIntermediateDirectories: true)
            try FileManager.default.createDirectory(at: provisioningDir, withIntermediateDirectories: true)
            if !LocalAnisetteProvider.validateLibrariesExist(at: libsDir) {
                try await setupFromRemote(serverSourceURL: sourceURL, fallbackODAURL: fallbackURL, clientInfo: clientInfo)
            }

            let provider = try await ensureProviderLoaded(clientInfo: clientInfo)
            let (headers, newAdiPb) = try await provider.getHeaders(identifier: identifier, storage: .memory(existingBlob: existingAdiBlob))

            guard let machineID = headers["X-Apple-I-MD-M"],
                  let oneTimePassword = headers["X-Apple-I-MD"],
                  let routingInfoStr = headers["X-Apple-I-MD-RINFO"],
                  let routingInfo = UInt64(routingInfoStr),
                  let localUserID = headers["X-Apple-I-MD-LU"] ?? customLocalUserID else {
                throw AnisetteError.invalidAnisetteData
            }

            let serial = headers["X-Apple-I-SRL-NO"] ?? "0"
            let deviceUID = customDeviceID ?? identifier.uuidString.uppercased()

            let anisetteData = AnisetteData(
                machineID: machineID,
                oneTimePassword: oneTimePassword,
                localUserID: localUserID,
                routingInfo: routingInfo,
                deviceUniqueIdentifier: deviceUID,
                deviceSerialNumber: serial,
                deviceDescription: clientInfo,
                date: Date(),
                locale: customLocale,
                timeZone: customTimeZone
            )
            return (anisetteData, newAdiPb)
        }
    }

    public func fetchAnisetteDataWithFailover(
        servers: [URL],
        startIndex: Int = 0,
        identifier: UUID = UUID(),
        existingAdiBlob: Data? = nil,
        clientInfo: String = LocalAnisetteProvider.defaultClientInfo,
        customLocalUserID: String? = nil,
        customDeviceID: String? = nil,
        customLocale: Locale = .current,
        customTimeZone: TimeZone = .current,
        onError: (@Sendable (Error) async throws -> Bool)? = nil,
        onSuccess: (@Sendable (URL) -> Void)? = nil
    ) async throws -> (data: AnisetteData, newAdiBlob: Data?) {
        guard !servers.isEmpty else {
            debugLog("[Anisette Failover] Failed: No servers configured.")
            throw AnisetteError.noServersConfigured
        }

        let start = (startIndex >= 0 && startIndex < servers.count) ? startIndex : 0
        var lastError: Error?

        debugLog("[Anisette Failover] Starting failover across \(servers.count) servers (start index: \(start))...")

        for triedCount in 0..<servers.count {
            let currentIndex = (start + triedCount) % servers.count
            let serverURL = servers[currentIndex]
            debugLog("[Anisette Failover] Attempting server [\(triedCount + 1)/\(servers.count)]: \(serverURL.absoluteString)...")
            do {
                let result = try await fetchAnisetteData(
                    mode: .remote(server: serverURL),
                    identifier: identifier,
                    existingAdiBlob: existingAdiBlob,
                    clientInfo: clientInfo,
                    customLocalUserID: customLocalUserID,
                    customDeviceID: customDeviceID,
                    customLocale: customLocale,
                    customTimeZone: customTimeZone,
                    onError: onError
                )
                debugLog("[Anisette Failover] Successfully acquired Anisette data from \(serverURL.absoluteString)")
                onSuccess?(serverURL)
                return result
            } catch {
                lastError = error
                debugLog("[Anisette Failover] Server [\(triedCount + 1)/\(servers.count)] '\(serverURL.absoluteString)' failed: \(error.localizedDescription)")
            }
        }

        debugLog("[Anisette Failover] All \(servers.count) servers failed. Last error: \(lastError?.localizedDescription ?? "unknown")")
        throw lastError ?? AnisetteError.allServersFailed
    }

    public func fetchServerList(from sourceURL: URL) async throws -> AnisetteServerData {
        var request = URLRequest(url: sourceURL)
        request.cachePolicy = .reloadIgnoringLocalCacheData

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let httpResp = response as? HTTPURLResponse, (200...299).contains(httpResp.statusCode) else {
            let status = (response as? HTTPURLResponse)?.statusCode ?? -1
            throw AnisetteError.serverListFetchFailed("Server returned HTTP \(status)")
        }

        let decoder = JSONDecoder()
        return try decoder.decode(AnisetteServerData.self, from: data)
    }

    private func fetchV3Headers(
        server: URL,
        identifier: String,
        adiBlob: Data,
        clientInfo: String,
        customLocalUserID: String? = nil,
        customLocale: Locale,
        customTimeZone: TimeZone
    ) async throws -> (AnisetteData, Data?) {
        let baseURL = server.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard let v3HeadersURL = URL(string: "\(baseURL)/\(Constants.URLs.v3GetHeaders)") else {
            throw AnisetteError.invalidURL
        }
        var postReq = URLRequest(url: v3HeadersURL)
        postReq.timeoutInterval = 15
        postReq.httpMethod = "POST"
        postReq.setValue("application/json", forHTTPHeaderField: "Content-Type")
        postReq.cachePolicy = .reloadIgnoringLocalCacheData
        let cleanIdentifier = identifier.replacingOccurrences(of: "-", with: "")
        let payload: [String: String] = [
            "identifier": cleanIdentifier,
            "adi_pb": adiBlob.base64EncodedString()
        ]
        postReq.httpBody = try JSONSerialization.data(withJSONObject: payload)
        let (data, response) = try await URLSession.shared.data(for: postReq)
        guard let httpResp = response as? HTTPURLResponse, (200...299).contains(httpResp.statusCode),
              let json = try JSONSerialization.jsonObject(with: data) as? [String: String] else {
            throw AnisetteError.invalidAnisetteData
        }

        if let result = json["result"], result == "GetHeadersError" {
            let msg = json["message"] ?? "GetHeadersError"
            throw AnisetteError.badServerResponse(statusCode: -1, payload: msg)
        }

        let anisette = try Self.parseAnisetteData(
            from: json,
            defaultDeviceID: identifier,
            defaultClientInfo: clientInfo,
            defaultLocalUserID: customLocalUserID ?? "0",
            defaultLocale: customLocale,
            defaultTimeZone: customTimeZone
        )
        return (anisette, nil)
    }

    private func runRemoteProvisioningSession(
        server: URL,
        identifier: UUID,
        clientInfo: String
    ) async throws -> Data {
        let baseURL = server.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard let clientInfoURL = URL(string: "\(baseURL)/\(Constants.URLs.v3ClientInfo)") else {
            throw AnisetteError.invalidURL
        }

        verboseLog("[Anisette WS] Fetching client info from \(clientInfoURL.absoluteString)...")
        var clientInfoReq = URLRequest(url: clientInfoURL)
        clientInfoReq.cachePolicy = .reloadIgnoringLocalCacheData
        clientInfoReq.timeoutInterval = 10
        let (clientInfoData, clientInfoResp) = try await URLSession.shared.data(for: clientInfoReq)
        guard let httpResp = clientInfoResp as? HTTPURLResponse, (200...299).contains(httpResp.statusCode),
              let clientInfoJSON = try? JSONSerialization.jsonObject(with: clientInfoData) as? [String: Any] else {
            throw AnisetteError.badServerResponse(statusCode: (clientInfoResp as? HTTPURLResponse)?.statusCode ?? -1, payload: "Failed to fetch client_info from remote server")
        }

        let resolvedClientInfo = clientInfoJSON["client_info"] as? String ?? clientInfo
        let userAgent = clientInfoJSON["user_agent"] as? String ?? "akd/1.0 CFNetwork/1408.0.4 Darwin/22.5.0"
        let mdLu = clientInfoJSON["md_lu"] as? String ?? ""
        let mdRinfo = clientInfoJSON["md_rinfo"] as? String ?? "17106176"

        var req = URLRequest(url: Constants.URLs.grandSlamLookup)
        req.httpMethod = "GET"
        req.setValue("text/x-xml-plist", forHTTPHeaderField: "Content-Type")
        req.setValue(resolvedClientInfo, forHTTPHeaderField: "X-Mme-Client-Info")
        req.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        req.setValue(identifier.uuidString.uppercased(), forHTTPHeaderField: "X-Mme-Device-Id")
        if !mdLu.isEmpty {
            req.setValue(mdLu, forHTTPHeaderField: "X-Apple-I-MD-LU")
        }
        req.setValue(mdRinfo, forHTTPHeaderField: "X-Apple-I-MD-RINFO")

        verboseLog("[Anisette WS] Fetching Apple provisioning URLs from GSA...")
        let (lookupData, lookupResp) = try await URLSession.shared.data(for: req)
        guard let gsaResp = lookupResp as? HTTPURLResponse, (200...299).contains(gsaResp.statusCode),
              let plist = try PropertyListSerialization.propertyList(from: lookupData, options: [], format: nil) as? [String: Any],
              let urls = plist["urls"] as? [String: String],
              let startURLString = urls["midStartProvisioning"],
              let startURL = URL(string: startURLString),
              let endURLString = urls["midFinishProvisioning"],
              let endURL = URL(string: endURLString) else {
            let status = (lookupResp as? HTTPURLResponse)?.statusCode ?? -1
            let payload = String(data: lookupData, encoding: .utf8) ?? ""
            throw AnisetteError.badServerResponse(statusCode: status, payload: "Failed to parse Apple provisioning URLs from GSA lookup: \(payload)")
        }

        guard let httpURL = URL(string: "\(baseURL)/\(Constants.URLs.v3ProvisioningSession)"),
              var wsComponents = URLComponents(url: httpURL, resolvingAgainstBaseURL: true) else {
            throw AnisetteError.invalidURL
        }
        wsComponents.scheme = (wsComponents.scheme == "http") ? "ws" : "wss"
        guard let wsURL = wsComponents.url else {
            throw AnisetteError.invalidURL
        }

        verboseLog("[Anisette WS] Connecting to WebSocket: \(wsURL.absoluteString)...")
        let wsTask = URLSession.shared.webSocketTask(with: wsURL)
        wsTask.resume()
        defer {
            wsTask.cancel(with: .normalClosure, reason: nil)
        }

        func sendWSJSON(_ dict: [String: String]) async throws {
            let data = try JSONSerialization.data(withJSONObject: dict)
            let str = String(data: data, encoding: .utf8) ?? ""
            try await wsTask.send(.string(str))
        }

        func receiveWSJSON() async throws -> [String: Any] {
            let msg = try await wsTask.receive()
            let str: String
            switch msg {
            case .string(let s):
                str = s
            case .data(let d):
                str = String(data: d, encoding: .utf8) ?? ""
            @unknown default:
                str = ""
            }
            guard let jsonData = str.data(using: .utf8),
                  let json = try JSONSerialization.jsonObject(with: jsonData) as? [String: Any] else {
                throw AnisetteError.invalidAnisetteData
            }
            return json
        }

        let cleanIdentifier = identifier.uuidString.replacingOccurrences(of: "-", with: "")

        func postApple(url: URL, body: [String: Any]) async throws -> [String: Any] {
            var appleReq = URLRequest(url: url)
            appleReq.httpMethod = "POST"
            appleReq.setValue("text/x-xml-plist", forHTTPHeaderField: "Content-Type")
            appleReq.setValue(resolvedClientInfo, forHTTPHeaderField: "X-Mme-Client-Info")
            appleReq.setValue(userAgent, forHTTPHeaderField: "User-Agent")
            appleReq.setValue(cleanIdentifier.uppercased(), forHTTPHeaderField: "X-Mme-Device-Id")
            if !mdLu.isEmpty {
                appleReq.setValue(mdLu, forHTTPHeaderField: "X-Apple-I-MD-LU")
            }
            appleReq.setValue(mdRinfo, forHTTPHeaderField: "X-Apple-I-MD-RINFO")
            appleReq.httpBody = try PropertyListSerialization.data(fromPropertyList: body, format: .xml, options: 0)
            let (data, appleResp) = try await URLSession.shared.data(for: appleReq)
            guard let resPlist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] else {
                let status = (appleResp as? HTTPURLResponse)?.statusCode ?? -1
                let payload = String(data: data, encoding: .utf8) ?? ""
                throw AnisetteError.badServerResponse(statusCode: status, payload: "Invalid plist from Apple GSA: \(payload)")
            }
            return resPlist
        }

        while true {
            let json = try await receiveWSJSON()
            guard let result = json["result"] as? String else {
                throw AnisetteError.badServerResponse(statusCode: -1, payload: "Missing result in WebSocket response")
            }

            verboseLog("[Anisette WS] Step: \(result)")

            switch result {
            case "GiveIdentifier":
                try await sendWSJSON(["identifier": cleanIdentifier])

            case "GiveStartProvisioningData":
                let body: [String: Any] = [
                    "Header": [String: Any](),
                    "Request": [String: Any]()
                ]
                let resPlist = try await postApple(url: startURL, body: body)
                guard let responseDict = resPlist["Response"] as? [String: Any],
                      let spim = responseDict["spim"] as? String else {
                    throw AnisetteError.badServerResponse(statusCode: -1, payload: "Missing spim from Apple start provisioning")
                }
                try await sendWSJSON(["spim": spim])

            case "GiveEndProvisioningData":
                guard let cpim = json["cpim"] as? String else {
                    throw AnisetteError.badServerResponse(statusCode: -1, payload: "Missing cpim from server")
                }
                let body: [String: Any] = [
                    "Header": [String: Any](),
                    "Request": ["cpim": cpim]
                ]
                let resPlist = try await postApple(url: endURL, body: body)
                guard let responseDict = resPlist["Response"] as? [String: Any],
                      let ptm = responseDict["ptm"] as? String,
                      let tk = responseDict["tk"] as? String else {
                    throw AnisetteError.badServerResponse(statusCode: -1, payload: "Missing ptm/tk from Apple end provisioning")
                }
                try await sendWSJSON(["ptm": ptm, "tk": tk])

            case "ProvisioningSuccess":
                guard let adiPbStr = json["adi_pb"] as? String,
                      let adiPbData = Data(base64Encoded: adiPbStr), !adiPbData.isEmpty else {
                    throw AnisetteError.badServerResponse(statusCode: -1, payload: "Missing/invalid adi_pb in ProvisioningSuccess")
                }
                verboseLog("[Anisette WS] ProvisioningSuccess! Received adi.pb (\(adiPbData.count) bytes)")
                return adiPbData

            default:
                let msg = json["message"] as? String ?? result
                throw AnisetteError.badServerResponse(statusCode: -1, payload: "Remote provisioning error: \(msg)")
            }
        }
    }

    public func fetchODAInfo(from serverSourceURL: URL, fallbackODAURL: URL? = nil) async throws -> ODAInfo {
        var request = URLRequest(url: serverSourceURL)
        request.cachePolicy = .reloadIgnoringLocalCacheData

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let httpResp = response as? HTTPURLResponse, (200...299).contains(httpResp.statusCode) else {
            let status = (response as? HTTPURLResponse)?.statusCode ?? -1
            throw AnisetteError.downloadFailed("Server list request failed with HTTP \(status)")
        }

        let decoder = JSONDecoder()
        if let directInfo = try? decoder.decode(ODAInfo.self, from: data),
           directInfo.url != nil || directInfo.base64Payload != nil {
            return directInfo
        }

        let serverData = try? decoder.decode(AnisetteServerData.self, from: data)

        switch serverData?.oda {
        case .direct(let directInfo):
            return directInfo

        case .path(let pathString):
            let targetURL: URL
            if let direct = URL(string: pathString), direct.scheme != nil {
                targetURL = direct
            } else if let relative = URL(string: pathString, relativeTo: serverSourceURL)?.absoluteURL {
                targetURL = relative
            } else if let fallback = fallbackODAURL {
                targetURL = fallback
            } else {
                throw AnisetteError.missingODAEntry
            }

            var odaReq = URLRequest(url: targetURL)
            odaReq.cachePolicy = .reloadIgnoringLocalCacheData
            let (odaData, odaResp) = try await URLSession.shared.data(for: odaReq)
            guard let httpOdaResp = odaResp as? HTTPURLResponse, (200...299).contains(httpOdaResp.statusCode) else {
                let status = (odaResp as? HTTPURLResponse)?.statusCode ?? -1
                throw AnisetteError.downloadFailed("ODA metadata request failed with HTTP \(status)")
            }

            return try decoder.decode(ODAInfo.self, from: odaData)

        case .none:
            guard let fallbackURL = fallbackODAURL else {
                throw AnisetteError.missingODAEntry
            }

            var odaReq = URLRequest(url: fallbackURL)
            odaReq.cachePolicy = .reloadIgnoringLocalCacheData
            let (odaData, odaResp) = try await URLSession.shared.data(for: odaReq)
            guard let httpOdaResp = odaResp as? HTTPURLResponse, (200...299).contains(httpOdaResp.statusCode) else {
                let status = (odaResp as? HTTPURLResponse)?.statusCode ?? -1
                throw AnisetteError.downloadFailed("Fallback ODA metadata request failed with HTTP \(status)")
            }

            return try decoder.decode(ODAInfo.self, from: odaData)
        }
    }

    public func downloadAndCacheLibs(from oda: ODAInfo, clientInfo: String = LocalAnisetteProvider.defaultClientInfo) async throws {
        guard !isCaching else {
            while isCaching {
                try await Task.sleep(nanoseconds: Self.cachingPollingDelayNanoseconds)
            }
            return
        }
        isCaching = true
        defer { isCaching = false }

        let libDir = libsDir
        let prov = provisioningDir

        let fm = FileManager.default
        try fm.createDirectory(at: libDir, withIntermediateDirectories: true)
        try fm.createDirectory(at: prov, withIntermediateDirectories: true)

        let zipData: Data
        if let inlineBase64 = oda.base64Payload,
           let decoded = Data(base64Encoded: inlineBase64.trimmingCharacters(in: .whitespacesAndNewlines), options: .ignoreUnknownCharacters) {
            zipData = decoded
        } else if let urlStr = oda.url, let downloadURL = URL(string: urlStr) {
            var request = URLRequest(url: downloadURL)
            request.cachePolicy = .reloadIgnoringLocalCacheData
            let (downloadedData, response) = try await URLSession.shared.data(for: request)

            guard let httpResp = response as? HTTPURLResponse, (200...299).contains(httpResp.statusCode) else {
                let status = (response as? HTTPURLResponse)?.statusCode ?? -1
                throw AnisetteError.downloadFailed("Package download failed with HTTP \(status)")
            }

            let rawString = String(data: downloadedData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
            if let base64String = rawString,
               let decoded = Data(base64Encoded: base64String, options: .ignoreUnknownCharacters) {
                zipData = decoded
            } else {
                zipData = downloadedData
            }
        } else {
            throw AnisetteError.downloadFailed("No valid URL or Base64 payload in ODA configuration.")
        }

        if let expectedSHA = oda.sha256, !expectedSHA.isEmpty {
            let zipSHA = computeSHA256(data: zipData)
            if zipSHA.caseInsensitiveCompare(expectedSHA) != .orderedSame {
                debugLog("[AnisetteDataProvider] SHA-256 mismatch (expected: \(expectedSHA), actual: \(zipSHA)). Proceeding with extraction.")
            }
        }

        let tempZipURL = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".zip")
        try zipData.write(to: tempZipURL, options: .atomic)
        defer { try? fm.removeItem(at: tempZipURL) }

        try fm.unzipArchive(at: tempZipURL, to: libDir)

        guard LocalAnisetteProvider.validateLibrariesExist(at: libDir) else {
            throw AnisetteError.missingRequiredLibs(LocalAnisetteProvider.requiredLibraryNames)
        }

        let provider = try LocalAnisetteProvider(
            provisioningDir: prov,
            clientInfo: clientInfo
        ) {
            libDir
        }

        self.localProvider = provider
    }

    public func setupFromRemote(serverSourceURL: URL, fallbackODAURL: URL? = nil, clientInfo: String = LocalAnisetteProvider.defaultClientInfo) async throws {
        let odaInfo = try await fetchODAInfo(from: serverSourceURL, fallbackODAURL: fallbackODAURL)
        try await downloadAndCacheLibs(from: odaInfo, clientInfo: clientInfo)
    }

    public func ensureProviderLoaded(clientInfo: String = LocalAnisetteProvider.defaultClientInfo) async throws -> LocalAnisetteProvider {
        if let existing = self.localProvider {
            return existing
        }

        let libDir = libsDir
        let prov = provisioningDir

        if LocalAnisetteProvider.validateLibrariesExist(at: libDir) {
            let provider = try LocalAnisetteProvider(
                provisioningDir: prov,
                clientInfo: clientInfo
            ) {
                libDir
            }
            self.localProvider = provider
            return provider
        }

        throw AnisetteError.providerNotReady("ADI shared libraries missing locally at: \(libDir.path)")
    }

    private func computeSHA256(data: Data) -> String {
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
