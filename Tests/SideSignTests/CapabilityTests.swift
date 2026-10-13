//
//  CapabilityTests.swift
//  SideSignTests
//

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Testing
@testable import SideSign

/// Answers the legacy updateAppId.action request and the v1 bundleIds PATCH,
/// and records both requests.
final class CapabilityURLProtocol: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var requests: [(method: String, url: URL, body: Data)] = []
    nonisolated(unsafe) static var patchStatus = 200
    static let lock = NSLock()

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        var body = request.httpBody ?? Data()
        if body.isEmpty, let stream = request.httpBodyStream {
            stream.open()
            var buffer = [UInt8](repeating: 0, count: 4096)
            while stream.hasBytesAvailable {
                let n = stream.read(&buffer, maxLength: buffer.count)
                if n <= 0 { break }
                body.append(buffer, count: n)
            }
            stream.close()
        }
        let url = request.url!
        let method = request.httpMethod ?? "GET"
        Self.lock.withLock { Self.requests.append((method, url, body)) }

        let status: Int
        let data: Data
        if url.path.hasSuffix("updateAppId.action") {
            status = 200
            data = try! PropertyListSerialization.data(fromPropertyList: [
                "resultCode": 0,
                "appId": ["appIdId": "ABCDE12345", "name": "App", "identifier": "com.example.app",
                          "features": ["APG3427HIY": true]]
            ], format: .xml, options: 0)
        } else if Self.patchStatus == 200 {
            status = 200
            data = Data(#"{"data":{"id":"ABCDE12345","type":"bundleIds"}}"#.utf8)
        } else {
            status = Self.patchStatus
            data = Data(#"{"errors":[{"status":"409","code":"ENTITY_ERROR","title":"conflict","detail":"capability not allowed"}]}"#.utf8)
        }
        let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: nil)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

@Suite("Increased Memory Limit capability", .serialized)
struct CapabilityTests {
    let team = Team(identifier: "TEAM123456", name: "Free Team", type: .free)
    let session = Session(
        dsid: "1", authToken: "token",
        anisetteData: AnisetteData(machineID: "m", oneTimePassword: "o", localUserID: "l", routingInfo: "0",
                                   deviceID: "d", serialNumber: "0", clientInfo: "c", userAgent: "u",
                                   clientTime: "2026-10-05T00:00:00Z", locale: "en_US", timeZone: "UTC"),
        xcodeVersion: "11.2 (11B41)")

    func portal() -> DeveloperPortal {
        CapabilityURLProtocol.requests = []
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [CapabilityURLProtocol.self]
        return DeveloperPortal(session: URLSession(configuration: configuration))
    }

    @Test
    func freeTeamsAllowIncreasedMemoryLimit() {
        #expect(Feature.freeFeatures.contains(.increasedMemoryLimit))
        #expect(Feature(entitlement: .increasedMemoryLimit) == .increasedMemoryLimit)
        #expect(Feature.increasedMemoryLimit.capabilityID == "INCREASED_MEMORY_LIMIT")
        #expect(Feature.appGroups.capabilityID == nil)
    }

    @Test
    func updateAppIDEnablesTheCapabilityWithAV1Patch() async throws {
        CapabilityURLProtocol.patchStatus = 200
        let portal = portal()
        let appID = AppID(identifier: "ABCDE12345", name: "App", bundleIdentifier: "com.example.app",
                          features: [.appGroups: "true", .increasedMemoryLimit: "true"])
        _ = try await portal.updateAppID(appID, team: team, session: session)

        let requests = CapabilityURLProtocol.requests
        #expect(requests.count == 2)

        // The legacy request carries only legacy features.
        let legacy = try #require(requests.first)
        #expect(legacy.url.path.hasSuffix("/ios/updateAppId.action"))
        let legacyBody = try #require(PropertyListSerialization.propertyList(from: legacy.body, format: nil) as? [String: Any])
        #expect(legacyBody["APG3427HIY"] as? Bool == true)
        #expect(legacyBody["increasedMemoryLimit"] == nil)

        let patch = try #require(requests.last)
        #expect(patch.method == "PATCH")
        #expect(patch.url.absoluteString == "https://developerservices2.apple.com/services/v1/bundleIds/ABCDE12345")
        let json = try #require(JSONSerialization.jsonObject(with: patch.body) as? [String: Any])
        let data = try #require(json["data"] as? [String: Any])
        #expect(data["id"] as? String == "ABCDE12345")
        #expect(data["type"] as? String == "bundleIds")
        let attributes = try #require(data["attributes"] as? [String: Any])
        #expect(attributes["identifier"] as? String == "com.example.app")
        #expect(attributes["teamId"] as? String == "TEAM123456")
        let relationships = try #require(data["relationships"] as? [String: Any])
        let capabilities = try #require((relationships["bundleIdCapabilities"] as? [String: Any])?["data"] as? [[String: Any]])
        #expect(capabilities.count == 1)
        let capability = try #require(((capabilities.first?["relationships"] as? [String: Any])?["capability"] as? [String: Any])?["data"] as? [String: Any])
        #expect(capability["id"] as? String == "INCREASED_MEMORY_LIMIT")
        #expect((capabilities.first?["attributes"] as? [String: Any])?["enabled"] as? Bool == true)
    }

    @Test
    func noPatchWithoutTheFeature() async throws {
        let portal = portal()
        let appID = AppID(identifier: "ABCDE12345", name: "App", bundleIdentifier: "com.example.app",
                          features: [.appGroups: "true", .increasedMemoryLimit: "false"])
        _ = try await portal.updateAppID(appID, team: team, session: session)
        #expect(CapabilityURLProtocol.requests.count == 1)
    }

    @Test
    func aRefusedCapabilityDoesNotFailTheUpdate() async throws {
        CapabilityURLProtocol.patchStatus = 409
        defer { CapabilityURLProtocol.patchStatus = 200 }
        let portal = portal()
        let appID = AppID(identifier: "ABCDE12345", name: "App", bundleIdentifier: "com.example.app",
                          features: [.appGroups: "true", .increasedMemoryLimit: "true"])
        let updated = try await portal.updateAppID(appID, team: team, session: session)
        #expect(updated.identifier == "ABCDE12345")
        #expect(CapabilityURLProtocol.requests.count == 2)
    }
}
