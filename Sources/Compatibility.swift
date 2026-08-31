//
//  Compatibility.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
import CodeSignKit

public typealias AltSign                    = SideSignLogging
public typealias ALTLogging                 = SideSignLogging
public typealias ALTAccount                 = Account
public typealias ALTTeam                    = Team
public typealias ALTTeamType                = TeamType
public typealias ALTCertificate             = KeyStore
public typealias ALTX509Certificate         = X509Certificate
public typealias ALTDevice                  = Device
public typealias ALTDeviceType              = DeviceType
public typealias ALTAppID                   = AppID
public typealias ALTFeature                 = Feature
public typealias ALTEntitlement             = Entitlement
public typealias ALTAppGroup                = AppGroup
public typealias ALTApplication             = AppBundle
public typealias ALTProvisioningProfile     = ProvisioningProfile
public typealias ALTAnisetteData            = AnisetteData
public typealias ALTAppleAPISession         = Session
public typealias ALTAppleAPI                = DeveloperPortal
public typealias ALTAppleAPIService         = DeveloperPortal
public typealias ALTAppleAPIProtocol        = DeveloperPortalAPI
public typealias Signer                     = AppBundleSigner
public typealias ALTSigner                  = AppBundleSigner
public typealias ALTCodeSigner              = AppBundleSigner
public typealias ALTCodeSignerAPI           = CodeSignerAPI
public typealias ALTAppleAPIError           = DeveloperPortalError
public typealias ALTError                   = SignerError
public typealias ALTServerError             = ServerError
public typealias ALTCertificateError        = CertificateError
public typealias CertificatesManager        = CertificateParser
public typealias ALTTrustedPhoneNumber      = TrustedPhoneNumber
public typealias ALTTwoFactorDeliveryMode   = TwoFactorDeliveryMode
public typealias ALTTwoFactorMode           = TwoFactorMode
public typealias ALTTwoFactorAction         = TwoFactorAction

public let AltSignErrorDomain               = "com.altstore.AltSign"
public let ALTAppleAPIErrorDomain           = "com.altstore.AltSign.AppleAPI"
public let ALTUnderlyingAppleAPIErrorDomain = "com.altstore.AltSign.UnderlyingAppleAPI"
public let ALTAppNameErrorKey               = "ALTAppName"

public extension DeviceType {
    static let iphone: DeviceType = .iPhone
    static let ipad: DeviceType   = .iPad
    static let tv: DeviceType     = .appleTV
    static let watch: DeviceType  = .appleWatch
    static let vision: DeviceType = .visionPro
}

public extension SignerError {
    enum Code: Int, Sendable, Equatable, Hashable {
        case unknown                        = 0
        case invalidApp                     = 1
        case missingAppBundle               = 2
        case missingInfoPlist               = 3
        case missingProvisioningProfile     = 4
    }

    init(_ code: Code, userInfo: [String: Any]? = nil) {
        switch code {
        case .unknown:                      self = .unknown(cause: nil)
        case .invalidApp:                   self = .invalidApp(cause: "")
        case .missingAppBundle:             self = .missingAppBundle(path: "")
        case .missingInfoPlist:             self = .missingInfoPlist(path: "")
        case .missingProvisioningProfile:   self = .missingProvisioningProfile(bundleIdentifier: "")
        }
    }

    static func invalidApp(reason: String) -> SignerError {
        .invalidApp(cause: reason)
    }
}

extension SignerError: CustomNSError {
    public static var errorDomain: String { AltSignErrorDomain }
    public var errorCode: Int {
        switch self {
        case .unknown:                      return 0
        case .invalidApp:                   return 1
        case .missingAppBundle:             return 2
        case .missingInfoPlist:             return 3
        case .missingProvisioningProfile:   return 4
        }
    }
}

public extension Dictionary where Key == String {
    subscript(entitlement: Entitlement) -> Value? {
        get { self[entitlement.rawValue] }
        set { self[entitlement.rawValue] = newValue }
    }
}

public extension AppBundleSigner {
    init(team: Team, certificate: KeyStore) {
        self.init(team: team, keyStore: certificate)
    }

    var certificate: KeyStore { keyStore }
}

public extension KeyStore {
    init(x509: X509Certificate, privateKey: Data, password: String? = nil) {
        self.init(certificate: x509, privateKey: privateKey, password: password)
    }

    init(p12Data: Data) throws {
        try self.init(p12Data: p12Data, password: "")
    }

    var x509: X509Certificate { certificate }
    var serialNumber: String { certificate.serialNumber }
    var identifier: String? {
        get { certificate.identifier }
        set { certificate.identifier = newValue }
    }
    var name: String { certificate.name }
    var machineIdentifier: String? {
        get { certificate.machineIdentifier }
        set { certificate.machineIdentifier = newValue }
    }
    var machineName: String? {
        get { certificate.machineName }
        set { certificate.machineName = newValue }
    }
    var requesterEmail: String? {
        get { certificate.requesterEmail }
        set { certificate.requesterEmail = newValue }
    }
    var data: Data? { certificate.data }
    var p12Data: Data { (try? exportP12(password: nil)) ?? Data() }

    func encryptedP12Data(password: String) throws -> Data {
        try exportP12(password: password)
    }

    func unencryptedP12Data() throws -> Data {
        try exportP12(password: nil)
    }
}

public extension AppGroup {
    var groupIdentifier: String { identifier }
}

public extension Data {
    var isPKCS12: Bool {
        (try? KeyStore(p12Data: self, password: "")) != nil
    }
}

#if canImport(UIKit)
import UIKit
public extension AppBundle {
    var icon: UIImage? {
        guard let iconURL else { return nil }
        return UIImage(contentsOfFile: iconURL.path)
    }
}
#elseif canImport(AppKit)
import AppKit
public extension AppBundle {
    var icon: NSImage? {
        guard let iconURL else { return nil }
        return NSImage(contentsOf: iconURL)
    }
}
#endif

#if canImport(Darwin)
extension Feature: _ObjectiveCBridgeable {
    public typealias _ObjectiveCType = NSString

    public func _bridgeToObjectiveC() -> NSString {
        rawValue as NSString
    }

    public static func _forceBridgeFromObjectiveC(_ source: NSString, result: inout Feature?) {
        result = Feature(rawValue: source as String)
    }

    public static func _conditionallyBridgeFromObjectiveC(_ source: NSString, result: inout Feature?) -> Bool {
        result = Feature(rawValue: source as String)
        return true
    }

    public static func _unconditionallyBridgeFromObjectiveC(_ source: NSString?) -> Feature {
        Feature(rawValue: (source ?? "") as String)
    }

    init?(entitlement: String) {
        self.init(entitlement: Entitlement(entitlement))
    }
}

extension Entitlement: _ObjectiveCBridgeable {
    public typealias _ObjectiveCType = NSString

    public func _bridgeToObjectiveC() -> NSString {
        rawValue as NSString
    }

    public static func _forceBridgeFromObjectiveC(_ source: NSString, result: inout Entitlement?) {
        result = Entitlement(rawValue: source as String)
    }

    public static func _conditionallyBridgeFromObjectiveC(_ source: NSString, result: inout Entitlement?) -> Bool {
        result = Entitlement(rawValue: source as String)
        return true
    }

    public static func _unconditionallyBridgeFromObjectiveC(_ source: NSString?) -> Entitlement {
        Entitlement(rawValue: (source ?? "") as String)
    }
}
#endif

// Compatibility completion handler extensions on DeveloperPortalAPI for legacy callers
public extension DeveloperPortalAPI {
    func addAppGroup(withName name: String, groupIdentifier: String, team: Team, session: Session) async throws -> AppGroup {
        try await addAppGroup(name: name, groupIdentifier: groupIdentifier, team: team, session: session)
    }

    func update(_ appID: AppID, team: Team, session: Session) async throws -> AppID {
        try await updateAppID(appID, team: team, session: session)
    }

    func assign(_ appID: AppID, to appGroups: [AppGroup], team: Team, session: Session) async throws -> AppID {
        try await assignAppGroups(appGroups, to: appID, team: team, session: session)
    }

    func fetchTeams(for account: Account, session: Session, completionHandler: @escaping @Sendable ([Team]?, Error?) -> Void) {
        Task {
            do {
                let teams = try await self.fetchTeams(for: account, session: session)
                completionHandler(teams, nil)
            } catch {
                completionHandler(nil, error)
            }
        }
    }

    func fetchDevices(for team: Team, types: DeviceType, session: Session, completionHandler: @escaping @Sendable ([Device]?, Error?) -> Void) {
        Task {
            do {
                let devices = try await self.fetchDevices(for: team, types: types, session: session)
                completionHandler(devices, nil)
            } catch {
                completionHandler(nil, error)
            }
        }
    }

    func registerDevice(name: String, identifier: String, type: DeviceType, team: Team, session: Session, completionHandler: @escaping @Sendable (Device?, Error?) -> Void) {
        Task {
            do {
                let device = try await self.registerDevice(name: name, identifier: identifier, type: type, team: team, session: session)
                completionHandler(device, nil)
            } catch {
                completionHandler(nil, error)
            }
        }
    }

    func fetchCertificates(for team: Team, session: Session, completionHandler: @escaping @Sendable ([X509Certificate]?, Error?) -> Void) {
        Task {
            do {
                let certs = try await self.fetchCertificates(for: team, session: session)
                completionHandler(certs, nil)
            } catch {
                completionHandler(nil, error)
            }
        }
    }

    func fetchAccount(session: Session, completionHandler: @escaping @Sendable (Result<Account, Error>) -> Void) {
        Task {
            do {
                let account = try await self.fetchAccount(session: session)
                completionHandler(.success(account))
            } catch {
                completionHandler(.failure(error))
            }
        }
    }

    func authenticate(
        appleID: String,
        password: String,
        anisetteData: AnisetteData,
        xcodeVersion: String,
        verificationHandler: DeveloperPortal.VerificationHandler?,
        completionHandler: @escaping @Sendable (Account?, Session?, Error?) -> Void
    ) {
        Task {
            do {
                let authSession = try await self.authenticate(
                    appleID: appleID,
                    password: password,
                    anisetteData: anisetteData,
                    xcodeVersion: xcodeVersion,
                    verificationHandler: verificationHandler
                )
                completionHandler(authSession.account, authSession.session, nil)
            } catch {
                completionHandler(nil, nil, error)
            }
        }
    }

    func deleteAppID(_ appID: AppID, for team: Team, session: Session, completionHandler: @escaping @Sendable (Bool, Error?) -> Void) {
        Task {
            do {
                let success = try await self.deleteAppID(appID, for: team, session: session)
                completionHandler(success, nil)
            } catch {
                completionHandler(false, error)
            }
        }
    }
}

