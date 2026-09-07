//
//  AnisetteDataManager.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
import Crypto
import AnisetteKit

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

public actor AnisetteDataManager {
    public static let shared = AnisetteDataManager()

    public var activeMode: AnisetteMode?
    public nonisolated let baseAnisetteDirectory: URL
    private var localProvider: AnisetteClient?
    private var isCaching: Bool = false

    public static var defaultBaseDirectory: URL {
        #if os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
        if let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first {
            return appSupport.appendingPathComponent(Constants.Anisette.defaultBaseDirName, isDirectory: true)
        }
        #endif

        let env = ProcessInfo.processInfo.environment
        if let xdgConfig = env[Constants.Session.envXDGConfig], !xdgConfig.isEmpty {
            return URL(fileURLWithPath: xdgConfig).appendingPathComponent(Constants.Anisette.defaultBaseDirName, isDirectory: true)
        }
        if let appData = env[Constants.Session.envAppData], !appData.isEmpty {
            return URL(fileURLWithPath: appData).appendingPathComponent(Constants.Session.defaultDirName, isDirectory: true)
        }
        let home = env[Constants.Session.envHome] ?? NSHomeDirectory()
        return URL(fileURLWithPath: home, isDirectory: true).appendingPathComponent(Constants.Anisette.defaultBaseDirName, isDirectory: true)
    }

    public init(mode: AnisetteMode? = nil, baseDirectory: URL? = nil) {
        self.activeMode = mode
        self.baseAnisetteDirectory = baseDirectory ?? Self.defaultBaseDirectory
    }

    public func setMode(_ mode: AnisetteMode) {
        self.activeMode = mode
    }

    public nonisolated var localLibsDir: URL {
        baseAnisetteDirectory.appendingPathComponent(Constants.Anisette.localLibsSubdirectory, isDirectory: true)
    }

    public nonisolated var remoteLibsDir: URL {
        baseAnisetteDirectory.appendingPathComponent(Constants.Anisette.remoteLibsSubdirectory, isDirectory: true)
    }

    public nonisolated var provisioningDir: URL {
        baseAnisetteDirectory.appendingPathComponent(Constants.Anisette.provisioningSubdirectory, isDirectory: true)
    }

    public nonisolated var libsDir: URL {
        if AnisetteClient.validateLibrariesExist(at: localLibsDir) {
            return localLibsDir
        }
        return remoteLibsDir
    }

    public func isReady() -> Bool {
        AnisetteClient.validateLibrariesExist(at: libsDir)
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
           let httpResp = response as? HTTPURLResponse, httpResp.isSuccess {
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
           let httpResp = response as? HTTPURLResponse, httpResp.isSuccess {
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
        defaultDeviceID: String? = nil
    ) -> AnisetteRequestHeaders {
        var headers = AnisetteHeadersDTO.toHeaders(from: dictionary)
        if headers.deviceID == nil, let defaultDeviceID = defaultDeviceID {
            headers.deviceID = defaultDeviceID
        }
        return headers
    }

    public static func safeTimeZoneAbbreviation(for timeZone: TimeZone, date: Date = Date()) -> String {
        AnisetteKit.safeTimeZoneAbbreviation(for: timeZone, date: date)
    }

    public static func toHTTPHeaders(data: AnisetteRequestHeaders) -> [String: String] {
        AnisetteHeadersDTO.toDictionary(from: data)
    }

    public func fetchAnisetteData(
        mode: AnisetteMode? = nil,
        identifier: UUID,
        existingAdiBlob: Data? = nil,
        headers: AnisetteRequestHeaders? = nil,
        onError: (@Sendable (Error) async throws -> Bool)? = nil
    ) async throws -> (data: AnisetteRequestHeaders, newAdiBlob: Data?) {
        guard let resolvedMode = mode ?? self.activeMode else {
            throw AnisetteError.modeNotConfigured
        }

        let effectiveHeaders = headers ?? AnisetteRequestHeaders.defaultHeaders
        let clientInfo = effectiveHeaders.clientInfo ?? AnisetteConstants.defaultClientInfo
        let client = try await getClient(for: resolvedMode, clientInfo: clientInfo)

        do {
            let (rawHeaders, newBlob) = try await client.getAnisetteData(
                identifier: identifier,
                storage: .memory(existingBlob: existingAdiBlob),
                headers: effectiveHeaders
            )

            var anisetteData = AnisetteRequestHeaders(rawHeaders: rawHeaders)
            if anisetteData.deviceID == nil {
                anisetteData.deviceID = identifier.uuidString.uppercased()
            }

            return (anisetteData, newBlob)
        } catch {
            if let errorHandler = onError {
                let shouldContinue = try await errorHandler(error)
                guard shouldContinue else {
                    throw error
                }
            }
            throw error
        }
    }

    private func getClient(for mode: AnisetteMode, clientInfo: String) async throws -> AnisetteClient {
        switch mode {
        case .remote(let server):
            try FileManager.default.createDirectory(at: provisioningDir, withIntermediateDirectories: true)
            return try AnisetteClient(
                provisioningDir: provisioningDir,
                clientInfo: clientInfo,
                provider: RemoteAnisetteDataProvider(serverURL: server)
            )

        case .localODA(let libDir, let prov):
            let targetProvDir = prov ?? provisioningDir
            try FileManager.default.createDirectory(at: targetProvDir, withIntermediateDirectories: true)
            return try AnisetteClient(
                provisioningDir: targetProvDir,
                clientInfo: clientInfo,
                libraryDirectoryResolver: { libDir }
            )

        case .remoteODA(let sourceURL, let fallbackURL):
            try FileManager.default.createDirectory(at: libsDir, withIntermediateDirectories: true)
            try FileManager.default.createDirectory(at: provisioningDir, withIntermediateDirectories: true)
            if !AnisetteClient.validateLibrariesExist(at: libsDir) {
                try await setupFromRemote(serverSourceURL: sourceURL, fallbackODAURL: fallbackURL, clientInfo: clientInfo)
            }
            return try await ensureProviderLoaded(clientInfo: clientInfo)
        }
    }

    public func fetchAnisetteDataWithFailover(
        servers: [URL],
        startIndex: Int = 0,
        identifier: UUID,
        existingAdiBlob: Data? = nil,
        headers: AnisetteRequestHeaders? = nil,
        onError: (@Sendable (Error) async throws -> Bool)? = nil,
        onSuccess: (@Sendable (URL) -> Void)? = nil
    ) async throws -> (data: AnisetteRequestHeaders, newAdiBlob: Data?) {
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
                    headers: headers,
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
        guard let httpResp = response as? HTTPURLResponse, httpResp.isSuccess else {
            let status = (response as? HTTPURLResponse)?.safeStatusCode ?? -1
            throw AnisetteError.serverListFetchFailed("Server returned HTTP \(status)")
        }

        let decoder = JSONDecoder()
        return try decoder.decode(AnisetteServerData.self, from: data)
    }

    public func fetchODAInfo(from serverSourceURL: URL, fallbackODAURL: URL? = nil) async throws -> ODAInfo {
        var request = URLRequest(url: serverSourceURL)
        request.cachePolicy = .reloadIgnoringLocalCacheData

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let httpResp = response as? HTTPURLResponse, httpResp.isSuccess else {
            let status = (response as? HTTPURLResponse)?.safeStatusCode ?? -1
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
            let targetURL = (URL(string: pathString)?.scheme != nil ? URL(string: pathString) : URL(string: pathString, relativeTo: serverSourceURL)?.absoluteURL) ?? fallbackODAURL
            guard let url = targetURL else { throw AnisetteError.missingODAEntry }
            return try await fetchODAData(from: url)

        case .none:
            guard let fallbackURL = fallbackODAURL else {
                throw AnisetteError.missingODAEntry
            }
            return try await fetchODAData(from: fallbackURL)
        }
    }

    private func fetchODAData(from url: URL) async throws -> ODAInfo {
        var odaReq = URLRequest(url: url)
        odaReq.cachePolicy = .reloadIgnoringLocalCacheData
        let (odaData, odaResp) = try await URLSession.shared.data(for: odaReq)
        guard let httpOdaResp = odaResp as? HTTPURLResponse, httpOdaResp.isSuccess else {
            let status = (odaResp as? HTTPURLResponse)?.safeStatusCode ?? -1
            throw AnisetteError.downloadFailed("ODA metadata request failed with HTTP \(status)")
        }
        return try JSONDecoder().decode(ODAInfo.self, from: odaData)
    }

    public func downloadAndCacheLibs(from oda: ODAInfo, targetDirectory: URL? = nil, clientInfo: String = AnisetteConstants.defaultClientInfo) async throws {
        guard !isCaching else {
            while isCaching {
                try await Task.sleep(nanoseconds: Constants.Anisette.cachingPollingDelayNanoseconds)
            }
            return
        }
        isCaching = true
        defer { isCaching = false }

        let libDir = targetDirectory ?? remoteLibsDir
        let prov = provisioningDir
        let fm = FileManager.default

        try fm.createDirectory(at: libDir, withIntermediateDirectories: true)
        try fm.createDirectory(at: prov, withIntermediateDirectories: true)

        let zipData = try await resolveZipData(from: oda)

        if let expectedSHA = oda.sha256, !expectedSHA.isEmpty {
            let zipSHA = computeSHA256(data: zipData)
            if zipSHA.caseInsensitiveCompare(expectedSHA) != .orderedSame {
                debugLog("[AnisetteDataManager] SHA-256 mismatch (expected: \(expectedSHA), actual: \(zipSHA)). Proceeding with extraction.")
            }
        }

        let tempZipURL = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".zip")
        try zipData.write(to: tempZipURL, options: .atomic)
        defer { try? fm.removeItem(at: tempZipURL) }

        try fm.unzipArchive(at: tempZipURL, to: libDir)

        guard AnisetteClient.validateLibrariesExist(at: libDir) else {
            throw AnisetteError.missingRequiredLibs(AnisetteConstants.Libraries.requiredNames)
        }

        self.localProvider = try AnisetteClient(
            provisioningDir: prov,
            clientInfo: clientInfo,
            libraryDirectoryResolver: { libDir }
        )
    }

    private func resolveZipData(from oda: ODAInfo) async throws -> Data {
        if let inlineBase64 = oda.base64Payload,
           let decoded = Data(base64Encoded: inlineBase64.trimmingCharacters(in: .whitespacesAndNewlines), options: .ignoreUnknownCharacters) {
            return decoded
        }
        guard let urlStr = oda.url, let downloadURL = URL(string: urlStr) else {
            throw AnisetteError.downloadFailed("No valid URL or Base64 payload in ODA configuration.")
        }
        var request = URLRequest(url: downloadURL)
        request.cachePolicy = .reloadIgnoringLocalCacheData
        let (downloadedData, response) = try await URLSession.shared.data(for: request)
        guard let httpResp = response as? HTTPURLResponse, httpResp.isSuccess else {
            let status = (response as? HTTPURLResponse)?.safeStatusCode ?? -1
            throw AnisetteError.downloadFailed("Package download failed with HTTP \(status)")
        }
        if let rawString = String(data: downloadedData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
           let decoded = Data(base64Encoded: rawString, options: .ignoreUnknownCharacters) {
            return decoded
        }
        return downloadedData
    }

    public func setupFromRemote(serverSourceURL: URL, fallbackODAURL: URL? = nil, force: Bool = false, clientInfo: String = AnisetteConstants.defaultClientInfo) async throws {
        let targetLibDir = remoteLibsDir
        if !force && AnisetteClient.validateLibrariesExist(at: targetLibDir) {
            debugLog("[AnisetteDataManager] Remote libraries already present in \(targetLibDir.path), using cache.")
            return
        }
        let odaInfo = try await fetchODAInfo(from: serverSourceURL, fallbackODAURL: fallbackODAURL)
        try await downloadAndCacheLibs(from: odaInfo, targetDirectory: targetLibDir, clientInfo: clientInfo)
    }

    public func ensureProviderLoaded(clientInfo: String = AnisetteConstants.defaultClientInfo) async throws -> AnisetteClient {
        if let existing = self.localProvider {
            return existing
        }

        let libDir = libsDir
        let prov = provisioningDir

        if AnisetteClient.validateLibrariesExist(at: libDir) {
            let provider = try AnisetteClient(
                provisioningDir: prov,
                clientInfo: clientInfo,
                libraryDirectoryResolver: { libDir }
            )
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
