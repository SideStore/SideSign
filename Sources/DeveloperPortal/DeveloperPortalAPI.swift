//
//  DeveloperPortalAPI.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
import CodeSignKit

public struct TrustedPhoneNumber: Sendable, Hashable, Identifiable, Codable {
    public let id: String
    public let number: String

    public init(id: String, number: String) {
        self.id = id
        self.number = number
    }
}

public enum TwoFactorDeliveryMode: String, Sendable {
    case sms
    case voice
}

public enum TwoFactorMode: Sendable, Equatable {
    case trustedDevice(error: String? = nil)
    case sms(phoneNumbers: [TrustedPhoneNumber], activeID: String, error: String? = nil)
    case voice(phoneNumbers: [TrustedPhoneNumber], activeID: String, error: String? = nil)
}

public enum TwoFactorAction: Sendable {
    case code(String)
    case requestPhone(id: String, mode: TwoFactorDeliveryMode)
    case cancel
}

public extension DeveloperPortal {
    typealias VerificationHandler = @Sendable (TwoFactorMode, @escaping @Sendable (TwoFactorAction) -> Void) -> Void
}

public protocol DeveloperPortalAPI: Sendable {
    func authenticate(appleID unsanitizedAppleID: String, password: String, anisetteData: AnisetteData, xcodeVersion: String, machinePassword: String?, verificationHandler: DeveloperPortal.VerificationHandler?) async throws -> AuthSession
    func fetchAccount(session: Session) async throws -> Account
    func fetchTeams(for account: Account, session: Session) async throws -> [Team]
    
    func fetchCertificates(for team: Team, session: Session) async throws -> [X509Certificate]
    func addCertificate(machineName: String, to team: Team, session: Session) async throws -> KeyStore
    func revokeCertificate(_ certificate: X509Certificate, for team: Team, session: Session) async throws -> Bool
    
    func fetchDevices(for team: Team, types: DeviceType, session: Session) async throws -> [Device]
    func registerDevice(name: String, identifier: String, type: DeviceType, team: Team, session: Session) async throws -> Device
    func updateDevice(_ device: Device, team: Team, session: Session) async throws -> Device
    func disableDevice(_ device: Device, team: Team, session: Session) async throws -> Device
    func deleteDevice(_ device: Device, team: Team, session: Session) async throws -> Bool
    
    func fetchAppIDs(for team: Team, session: Session) async throws -> [AppID]
    func addAppID(withName name: String, bundleIdentifier: String, team: Team, session: Session) async throws -> AppID
    func updateAppID(_ appID: AppID, team: Team, session: Session) async throws -> AppID
    func deleteAppID(_ appID: AppID, for team: Team, session: Session) async throws -> Bool
    
    func fetchAppGroups(for team: Team, session: Session) async throws -> [AppGroup]
    func addAppGroup(name: String, groupIdentifier: String, team: Team, session: Session) async throws -> AppGroup
    func updateAppGroup(_ appGroup: AppGroup, team: Team, session: Session) async throws -> AppGroup
    func assignAppGroups(_ appGroups: [AppGroup], to appID: AppID, team: Team, session: Session) async throws -> AppID
    func deleteAppGroup(_ appGroup: AppGroup, team: Team, session: Session) async throws -> Bool

    func fetchProvisioningProfiles(for team: Team, session: Session) async throws -> [ProvisioningProfile]
    func downloadProvisioningProfile(for appID: AppID, deviceType: DeviceType, team: Team, session: Session) async throws -> ProvisioningProfile
    func deleteProvisioningProfile(_ profile: ProvisioningProfile, team: Team, session: Session) async throws -> Bool

    func fetchAuthDevices(session: Session) async throws -> [AuthDevice]
    func removeAuthDevice(id: String, session: Session) async throws -> Bool
}

public extension DeveloperPortalAPI {
    func authenticate(appleID unsanitizedAppleID: String, password: String, anisetteData: AnisetteData, xcodeVersion: String, verificationHandler: DeveloperPortal.VerificationHandler? = nil) async throws -> AuthSession {
        try await authenticate(appleID: unsanitizedAppleID, password: password, anisetteData: anisetteData, xcodeVersion: xcodeVersion, machinePassword: nil, verificationHandler: verificationHandler)
    }

    func authenticate(appleID unsanitizedAppleID: String, password: String, anisetteData: AnisetteData, xcodeVersion: String, machinePassword: String?) async throws -> AuthSession {
        try await authenticate(appleID: unsanitizedAppleID, password: password, anisetteData: anisetteData, xcodeVersion: xcodeVersion, machinePassword: machinePassword, verificationHandler: nil)
    }

    func fetchDevices(for team: Team, session: Session) async throws -> [Device] {
        try await fetchDevices(for: team, types: .all, session: session)
    }

    func downloadProvisioningProfile(for appID: AppID, team: Team, session: Session) async throws -> ProvisioningProfile {
        try await downloadProvisioningProfile(for: appID, deviceType: .iPhone, team: team, session: session)
    }

    func fetchProvisioningProfile(for appID: AppID, deviceType: DeviceType, team: Team, session: Session) async throws -> ProvisioningProfile {
        try await downloadProvisioningProfile(for: appID, deviceType: deviceType, team: team, session: session)
    }

    func fetchProvisioningProfile(for appID: AppID, team: Team, session: Session) async throws -> ProvisioningProfile {
        try await downloadProvisioningProfile(for: appID, deviceType: .iPhone, team: team, session: session)
    }
}

public final class DeveloperPortal: DeveloperPortalAPI, Sendable {

    public static let shared = DeveloperPortal()

    public let baseURL         = Constants.URLs.developerServicesBase
    public let servicesBaseURL = Constants.URLs.developerServicesV1Base

    let session: URLSession

    public init(session: URLSession = .shared) {
        self.session = session
    }

    func formatDate(_ date: Date) -> String {
        ISO8601DateFormatter().string(from: date)
    }

    public func fetchAccount(session: Session) async throws -> Account {
        debugLog("[SideSign] fetchAccount starting...")
        verboseLog("[SideSign] DSID: \(session.dsid)")

        let response: ViewDeveloperResponse = try await sendRequest(url: Constants.URLs.viewDeveloper, session: session)

        guard let developer = response.developer else {
            debugLog("[SideSign] fetchAccount error: Missing developer account information in response")
            throw ServerError.badServerResponse(reason: "Missing developer account information", jsonPayload: "")
        }

        let account = developer.toAccount()
        debugLog("[SideSign] fetchAccount succeeded")
        verboseLog("[SideSign] Account: \(account.name) (\(account.appleID))")
        return account
    }

    // XML Plist Request Dispatcher
    func sendRequest<T: Decodable>(url requestURL: URL,
                                   additionalParameters: [String: any Sendable]? = nil,
                                   session apiSession: Session,
                                   team: Team? = nil,
                                   resultCodeHandler: ((Int, String) -> Error?)? = nil) async throws -> T
    {
        var parameters: [String: any Sendable] = [
            "clientId": Constants.clientID,
            "protocolVersion": Constants.protocolVersion,
            "requestId": UUID().uuidString.uppercased()
        ]

        if let team {
            parameters["teamId"] = team.identifier
        }

        additionalParameters?.forEach { parameters[$0] = $1 }

        let bodyData = try PropertyListSerialization.data(
            fromPropertyList: parameters,
            format: .xml,
            options: 0
        )

        let url = URL(string: "\(requestURL.absoluteString)?clientId=\(Constants.clientID)")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = bodyData

        let a = apiSession.anisetteData
        let headers: [String: String] = [
            "Content-Type": "text/x-xml-plist",
            "User-Agent": Constants.xcodeUserAgent,
            "Accept": "text/x-xml-plist",
            "Accept-Language": "en-us",
            "X-Apple-App-Info": Constants.authApp,
            "X-Xcode-Version": apiSession.xcodeVersion,
            "X-Apple-I-Identity-Id": apiSession.dsid,
            "X-Apple-GS-Token": apiSession.authToken,
            "X-Apple-I-MD-M": a.machineID,
            "X-Apple-I-MD": a.oneTimePassword,
            "X-Apple-I-MD-LU": a.localUserID,
            "X-Apple-I-MD-RINFO": "\(a.routingInfo)",
            "X-Mme-Device-Id": a.deviceUniqueIdentifier,
            "X-MMe-Client-Info": a.deviceDescription,
            "X-Apple-I-Client-Time": formatDate(a.date),
            "X-Apple-Locale": a.locale.identifier,
            "X-Apple-I-Locale": a.locale.identifier,
            "X-Apple-I-TimeZone": a.timeZone.abbreviation(for: a.date) ?? ""
        ]

        headers.forEach { request.setValue($1, forHTTPHeaderField: $0) }

        verboseLog("[SideSign] sendRequest: \(url.absoluteString)")

        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            debugLog("[SideSign] sendRequest network error: \(error)")
            throw error
        }

        let httpResponse = response as? HTTPURLResponse
        let statusCode = httpResponse?.statusCode ?? 0

        guard !data.isEmpty else {
            if statusCode == HTTPStatusCodes.noContent || T.self == EmptyResponse.self {
                if let empty = EmptyResponse() as? T {
                    return empty
                }
            }
            debugLog("[SideSign] sendRequest server returned 0 bytes (HTTP \(statusCode))")
            throw ServerError.badServerResponse(reason: "Server returned empty response (Content-Length: 0)", jsonPayload: "0 bytes")
        }

        if let payloadString = formatPayload(data) {
            verboseLog("[SideSign] sendRequest response: \(payloadString)")
        }

        if let status = (try? PropertyListDecoder().decode(DeveloperPortalStatusResponse.self, from: data))
            ?? (try? JSONDecoder().decode(DeveloperPortalStatusResponse.self, from: data)) {
            if let errors = status.errors, let firstError = errors.first, let detail = firstError.detail {
                debugLog("[SideSign] processResponse parsed Apple developer API error: \(detail)")
                throw ServerError.underlyingError(code: -1, message: detail)
            }
            if let code = status.resultCode, code != DeveloperPortalResultCodes.success {
                let message = status.userString ?? status.resultString ?? status.errorString ?? "Apple Developer Portal Error"
                if let customError = resultCodeHandler?(code, message) {
                    debugLog("[SideSign] processResponse error (code: \(code)): \(customError.localizedDescription)")
                    throw customError
                }
                debugLog("[SideSign] processResponse error: \(message) (code: \(code))")
                throw ServerError.underlyingError(code: code, message: message)
            }
        }

        do {
            if let plistDecoded = try? PropertyListDecoder().decode(T.self, from: data) {
                return plistDecoded
            }
            return try JSONDecoder().decode(T.self, from: data)
        } catch {
            let rawStr = String(data: data, encoding: .utf8) ?? data.hexEncodedString()
            debugLog("[SideSign] sendRequest failed to decode \(T.self): \(error). Raw payload: \(rawStr)")
            throw ServerError.invalidResponseFormat(rawPayload: rawStr)
        }
    }

    // JSON Services Request Dispatcher
    func sendServicesRequest<T: Decodable>(_ originalRequest: URLRequest,
                                           additionalParameters: [String: String]? = nil,
                                           session apiSession: Session,
                                           team: Team,
                                           includeAnisette: Bool = true,
                                           resultCodeHandler: ((Int, String) -> Error?)? = nil) async throws -> T
    {
        var request = originalRequest

        var items = [URLQueryItem(name: "teamId", value: team.identifier)]
        additionalParameters?.forEach { items.append(.init(name: $0, value: $1)) }

        var comps = URLComponents()
        comps.queryItems = items
        let query = comps.query ?? ""

        let bodyData = try JSONSerialization.data(withJSONObject: ["urlEncodedQueryParams": query])
        let methodOverride = request.httpMethod ?? "GET"

        request.httpMethod = "POST"
        request.httpBody = bodyData
        request.setValue(methodOverride, forHTTPHeaderField: "X-HTTP-Method-Override")

        var headers: [String: String] = [
            "Content-Type": "application/vnd.api+json",
            "User-Agent": Constants.xcodeUserAgent,
            "Accept": "application/vnd.api+json",
            "Accept-Language": "en-us",
            "X-Apple-App-Info": Constants.authApp,
            "X-Xcode-Version": apiSession.xcodeVersion,
            "X-Apple-I-Identity-Id": apiSession.dsid,
            "X-Apple-GS-Token": apiSession.authToken
        ]

        if includeAnisette {
            let a = apiSession.anisetteData
            headers["X-Apple-I-MD-M"] = a.machineID
            headers["X-Apple-I-MD"] = a.oneTimePassword
            headers["X-Apple-I-MD-LU"] = a.localUserID
            headers["X-Apple-I-MD-RINFO"] = "\(a.routingInfo)"
            headers["X-Mme-Device-Id"] = a.deviceUniqueIdentifier
            headers["X-MMe-Client-Info"] = a.deviceDescription
            headers["X-Apple-I-Client-Time"] = formatDate(Date())
            headers["X-Apple-Locale"] = a.locale.identifier
            headers["X-Apple-I-TimeZone"] = a.timeZone.abbreviation(for: Date()) ?? ""
        }

        headers.forEach { request.setValue($1, forHTTPHeaderField: $0) }

        verboseLog("[SideSign] sendServicesRequest to: \(request.url?.absoluteString ?? "unknown URL")")
        verboseLog("[SideSign] sendServicesRequest parameters: \(additionalParameters ?? [:])")

        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            debugLog("[SideSign] sendServicesRequest network error: \(error)")
            throw error
        }

        let httpResponse = response as? HTTPURLResponse
        let statusCode = httpResponse?.statusCode ?? 0
        let isDelete = methodOverride == "DELETE"
        let isNoContent = statusCode == HTTPStatusCodes.noContent

        guard !data.isEmpty else {
            if isDelete || isNoContent || T.self == EmptyResponse.self {
                verboseLog("[SideSign] sendServicesRequest: successful empty response for DELETE or \(HTTPStatusCodes.noContent)")
                if let empty = EmptyResponse() as? T {
                    return empty
                }
            }
            debugLog("[SideSign] sendServicesRequest server returned 0 bytes (HTTP \(statusCode))")
            throw ServerError.badServerResponse(reason: "Server returned empty response", jsonPayload: "0 bytes")
        }

        if let payloadString = formatPayload(data) {
            verboseLog("[SideSign] sendServicesRequest response: \(payloadString)")
        }

        if let status = try? JSONDecoder().decode(DeveloperPortalStatusResponse.self, from: data) {
            if let errors = status.errors, let firstError = errors.first, let detail = firstError.detail {
                debugLog("[SideSign] processResponse parsed Apple developer API error: \(detail)")
                throw ServerError.underlyingError(code: -1, message: detail)
            }
            if let code = status.resultCode, code != DeveloperPortalResultCodes.success {
                let message = status.userString ?? status.resultString ?? status.errorString ?? "Apple Developer Portal Error"
                if let customError = resultCodeHandler?(code, message) {
                    debugLog("[SideSign] processResponse error (code: \(code)): \(customError.localizedDescription)")
                    throw customError
                }
                debugLog("[SideSign] processResponse error: \(message) (code: \(code))")
                throw ServerError.underlyingError(code: code, message: message)
            }
        }

        do {
            return try JSONDecoder().decode(T.self, from: data)
        } catch {
            if isDelete || isNoContent, let empty = EmptyResponse() as? T {
                return empty
            }
            let rawStr = String(data: data, encoding: .utf8) ?? data.hexEncodedString()
            debugLog("[SideSign] sendServicesRequest failed to decode \(T.self): \(error). Raw payload: \(rawStr)")
            throw ServerError.invalidResponseFormat(rawPayload: rawStr)
        }
    }
}
