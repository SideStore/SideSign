//
//  RemoteAnisetteDataProvider.swift
//  SideSign
//
//  Created by Magesh K on 07/09/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
import AnisetteKit

public struct RemoteAnisetteDataProvider: AnisetteDataProvider, Sendable {
    public var requiresLocalLibraries: Bool { false }

    public let serverURL: URL

    private final class ProvisioningSessionManager: @unchecked Sendable {
        private let lock = NSLock()
        private var counter: UInt32 = 0
        private var activeSessions: [UInt32: URLSessionWebSocketTask] = [:]

        func store(_ task: URLSessionWebSocketTask) -> UInt32 {
            lock.withLock {
                counter &+= 1
                if counter == 0 { counter = 1 }
                activeSessions[counter] = task
                return counter
            }
        }

        func retrieve(for session: UInt32) -> URLSessionWebSocketTask? {
            lock.withLock {
                activeSessions.removeValue(forKey: session)
            }
        }

        func cancelAll() {
            lock.withLock {
                for task in activeSessions.values {
                    task.cancel(with: .normalClosure, reason: nil)
                }
                activeSessions.removeAll()
            }
        }
    }

    private static let sessionManager = ProvisioningSessionManager()

    public init(serverURL: URL) {
        self.serverURL = serverURL
    }

    public func getAnisetteHeaders(
        libDir: String,
        provisioningDir: String,
        identifier: [UInt8],
        adiPb: [UInt8]
    ) async throws -> AnisetteDataResponse {
        let cleanIdentifier = identifier.map { String(format: "%02x", $0) }.joined()
        let baseURL = serverURL.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/"))

        // 1. If adiPb is present, attempt v3 /v3/get_headers
        if !adiPb.isEmpty {
            if let v3HeadersURL = URL(string: "\(baseURL)/\(Constants.URLs.v3GetHeaders)") {
                var postReq = URLRequest(url: v3HeadersURL)
                postReq.timeoutInterval = 15
                postReq.httpMethod = "POST"
                postReq.setValue("application/json", forHTTPHeaderField: "Content-Type")
                postReq.cachePolicy = .reloadIgnoringLocalCacheData

                let payload: [String: String] = [
                    "identifier": cleanIdentifier,
                    "adi_pb": Data(adiPb).base64EncodedString()
                ]
                postReq.httpBody = try JSONSerialization.data(withJSONObject: payload)

                if let (data, response) = try? await URLSession.shared.data(for: postReq),
                   let httpResp = response as? HTTPURLResponse, httpResp.isSuccess,
                   let json = try? JSONSerialization.jsonObject(with: data) as? [String: String] {
                    if let result = json["result"], result == "GetHeadersError" {
                        let msg = json["message"] ?? "GetHeadersError"
                        throw AnisetteError.badServerResponse(statusCode: -1, payload: msg)
                    }
                    return try AnisetteDataResponse(from: json)
                }
            }
        }

        // 2. Fallback to legacy v1 root GET
        var request = URLRequest(url: serverURL)
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.timeoutInterval = 15

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let httpResp = response as? HTTPURLResponse, httpResp.isSuccess else {
            let status = (response as? HTTPURLResponse)?.statusCode ?? -1
            let payload = String(data: data, encoding: .utf8) ?? ""
            throw AnisetteError.badServerResponse(statusCode: status, payload: payload)
        }

        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: String] else {
            throw AnisetteError.invalidAnisetteData
        }

        return try AnisetteDataResponse(from: json)
    }

    public func startProvision(
        libDir: String,
        provisioningDir: String,
        identifier: [UInt8],
        spim: [UInt8]
    ) async throws -> (cpim: Data, session: UInt32) {
        let baseURL = serverURL.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard let httpURL = URL(string: "\(baseURL)/\(Constants.URLs.v3ProvisioningSession)"),
              var webSocketComponents = URLComponents(url: httpURL, resolvingAgainstBaseURL: true) else {
            throw AnisetteError.invalidURL
        }
        webSocketComponents.scheme = (webSocketComponents.scheme == "http") ? "ws" : "wss"
        guard let webSocketURL = webSocketComponents.url else {
            throw AnisetteError.invalidURL
        }

        let webSocketTask = URLSession.shared.webSocketTask(with: webSocketURL)
        webSocketTask.resume()

        let cleanIdentifier = identifier.map { String(format: "%02x", $0) }.joined()

        do {
            while true {
                let json = try await receiveWebSocketJSON(from: webSocketTask)
                guard let result = json["result"] as? String else {
                    throw AnisetteError.badServerResponse(statusCode: -1, payload: "Missing result in WebSocket response")
                }

                switch result {
                case "GiveIdentifier":
                    try await sendWebSocketJSON(["identifier": cleanIdentifier], to: webSocketTask)

                case "GiveStartProvisioningData":
                    let spimBase64 = Data(spim).base64EncodedString()
                    try await sendWebSocketJSON(["spim": spimBase64], to: webSocketTask)

                case "GiveEndProvisioningData":
                    guard let cpimBase64 = json["cpim"] as? String,
                          let cpimData = Data(base64Encoded: cpimBase64) else {
                        throw AnisetteError.badServerResponse(statusCode: -1, payload: "Missing or invalid cpim in GiveEndProvisioningData")
                    }
                    let sessionKey = Self.sessionManager.store(webSocketTask)
                    return (cpimData, sessionKey)

                default:
                    let msg = json["message"] as? String ?? result
                    throw AnisetteError.badServerResponse(statusCode: -1, payload: "Unexpected remote provisioning step: \(msg)")
                }
            }
        } catch {
            webSocketTask.cancel(with: .normalClosure, reason: nil)
            throw error
        }
    }

    public func endProvision(
        libDir: String,
        provisioningDir: String,
        identifier: [UInt8],
        session: UInt32,
        ptm: [UInt8],
        tk: [UInt8]
    ) async throws -> Data {
        guard let webSocketTask = Self.sessionManager.retrieve(for: session) else {
            throw AnisetteError.badServerResponse(statusCode: -1, payload: "Active WebSocket session not found for id \(session)")
        }
        defer {
            webSocketTask.cancel(with: .normalClosure, reason: nil)
        }

        let ptmBase64 = Data(ptm).base64EncodedString()
        let tkBase64 = Data(tk).base64EncodedString()
        try await sendWebSocketJSON(["ptm": ptmBase64, "tk": tkBase64], to: webSocketTask)

        while true {
            let json = try await receiveWebSocketJSON(from: webSocketTask)
            guard let result = json["result"] as? String else {
                throw AnisetteError.badServerResponse(statusCode: -1, payload: "Missing result in WebSocket response")
            }

            switch result {
            case "ProvisioningSuccess":
                guard let adiPbStr = json["adi_pb"] as? String,
                      let adiPbData = Data(base64Encoded: adiPbStr), !adiPbData.isEmpty else {
                    throw AnisetteError.badServerResponse(statusCode: -1, payload: "Missing/invalid adi_pb in ProvisioningSuccess")
                }
                return adiPbData

            default:
                let msg = json["message"] as? String ?? result
                throw AnisetteError.badServerResponse(statusCode: -1, payload: "Remote provisioning end error: \(msg)")
            }
        }
    }

    private func sendWebSocketJSON(_ dict: [String: String], to webSocketTask: URLSessionWebSocketTask) async throws {
        let data = try JSONSerialization.data(withJSONObject: dict)
        guard let str = String(data: data, encoding: .utf8) else {
            throw AnisetteError.invalidAnisetteData
        }
        try await webSocketTask.send(.string(str))
    }

    private func receiveWebSocketJSON(from webSocketTask: URLSessionWebSocketTask) async throws -> [String: Any] {
        let msg = try await webSocketTask.receive()
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
}
