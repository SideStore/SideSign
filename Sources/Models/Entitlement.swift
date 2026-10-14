//
//  Entitlement.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation

public struct Entitlement: RawRepresentable, Hashable, Codable, Sendable, ExpressibleByStringLiteral {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public init(_ rawValue: String) {
        self.rawValue = rawValue
    }

    public init(stringLiteral value: String) {
        self.rawValue = value
    }
}

public extension Entitlement {
    static let appGroups: Entitlement                       = "com.apple.security.application-groups"
    static let keychainAccessGroups: Entitlement            = "keychain-access-groups"
    static let getTaskAllow: Entitlement                    = "get-task-allow"
    static let applicationIdentifier: Entitlement           = "application-identifier"
    static let teamIdentifier: Entitlement                  = "com.apple.developer.team-identifier"

    static let increasedDebuggingMemoryLimit: Entitlement   = "com.apple.developer.kernel.increased-debugging-memory-limit"
    static let increasedMemoryLimit: Entitlement            = "com.apple.developer.kernel.increased-memory-limit"
    static let extendedVirtualAddressing: Entitlement       = "com.apple.developer.kernel.extended-virtual-addressing"

    static let interAppAudio: Entitlement                   = "inter-app-audio"
    static let associatedDomains: Entitlement               = "com.apple.developer.associated-domains"
    static let dataProtection: Entitlement                  = "com.apple.developer.default-data-protection"
    static let siri: Entitlement                            = "com.apple.developer.siri"
    static let applePay: Entitlement                        = "com.apple.developer.in-app-payments"
    static let vpn: Entitlement                             = "com.apple.developer.networking.vpn.api"
    static let networkExtensions: Entitlement               = "com.apple.developer.networking.networkextension"
    static let multipath: Entitlement                       = "com.apple.developer.networking.multipath"
    static let hotspot: Entitlement                         = "com.apple.developer.networking.HotspotConfiguration"
    static let nfc: Entitlement                             = "com.apple.developer.nfc.readersession.formats"
    static let classKit: Entitlement                        = "com.apple.developer.ClassKit-environment"
    static let autoFillCredentialProvider: Entitlement      = "com.apple.developer.authentication-services.autofill-credential-provider"
    static let accessWiFiInformation: Entitlement           = "com.apple.developer.networking.wifi-info"
    static let wirelessAccessoryConfiguration: Entitlement  = "com.apple.external-accessory.wireless-configuration"
    static let pushNotifications: Entitlement               = "aps-environment"
    static let gameCenter: Entitlement                      = "game-center"
    static let inAppPurchase: Entitlement                   = "in-app-purchase"

    static let appleSignIn: Entitlement                     = "com.apple.developer.applesignin"
    static let iCloudServices: Entitlement                  = "com.apple.developer.icloud-services"
    static let iCloudContainerIdentifiers: Entitlement      = "com.apple.developer.icloud-container-identifiers"
    static let ubiquityKeyValueStore: Entitlement           = "com.apple.developer.ubiquity-kvstore-identifier"
    static let healthKit: Entitlement                       = "com.apple.developer.healthkit"
    static let healthKitAccess: Entitlement                 = "com.apple.developer.healthkit.access"
    static let homeKit: Entitlement                         = "com.apple.developer.homekit"
    static let criticalAlerts: Entitlement                  = "com.apple.developer.usernotifications.critical-alerts"
    static let timeSensitiveNotifications: Entitlement      = "com.apple.developer.usernotifications.time-sensitive"
    static let communicationNotifications: Entitlement      = "com.apple.developer.usernotifications.communication"
    static let groupSession: Entitlement                    = "com.apple.developer.group-session"
    static let weatherKit: Entitlement                      = "com.apple.developer.weatherkit"
    static let userFonts: Entitlement                       = "com.apple.developer.user-fonts"
    static let carPlayMaps: Entitlement                     = "com.apple.developer.carplay-maps"
    static let carPlayAudio: Entitlement                    = "com.apple.developer.carplay-audio"
    static let appAttest: Entitlement                       = "com.apple.developer.devicecheck.appattest-environment"

    static let freeEntitlements: Set<Entitlement> = [
        .appGroups,
        .interAppAudio,
        .getTaskAllow,
        .increasedMemoryLimit,
        .increasedDebuggingMemoryLimit,
        .extendedVirtualAddressing,
        .teamIdentifier,
        .keychainAccessGroups,
        .applicationIdentifier,
        .healthKit
    ]

    static let paidEntitlements: Set<Entitlement> = [
        .appGroups,
        .interAppAudio,
        .getTaskAllow,
        .increasedMemoryLimit,
        .increasedDebuggingMemoryLimit,
        .extendedVirtualAddressing,
        .teamIdentifier,
        .keychainAccessGroups,
        .applicationIdentifier,
        .associatedDomains,
        .dataProtection,
        .siri,
        .applePay,
        .vpn,
        .networkExtensions,
        .multipath,
        .hotspot,
        .nfc,
        .classKit,
        .autoFillCredentialProvider,
        .accessWiFiInformation,
        .wirelessAccessoryConfiguration,
        .pushNotifications,
        .gameCenter,
        .inAppPurchase,
        .appleSignIn,
        .iCloudServices,
        .iCloudContainerIdentifiers,
        .ubiquityKeyValueStore,
        .healthKit,
        .healthKitAccess,
        .homeKit,
        .criticalAlerts,
        .timeSensitiveNotifications,
        .communicationNotifications,
        .groupSession,
        .weatherKit,
        .userFonts,
        .carPlayMaps,
        .carPlayAudio,
        .appAttest
    ]

    static let allKnown: [Entitlement] = [
        .increasedMemoryLimit,
        .extendedVirtualAddressing,
        .increasedDebuggingMemoryLimit,
        .getTaskAllow,
        .appGroups,
        .keychainAccessGroups,
        .interAppAudio,
        .pushNotifications,
        .associatedDomains,
        .appleSignIn,
        .iCloudServices,
        .iCloudContainerIdentifiers,
        .ubiquityKeyValueStore,
        .healthKit,
        .healthKitAccess,
        .homeKit,
        .criticalAlerts,
        .timeSensitiveNotifications,
        .communicationNotifications,
        .groupSession,
        .weatherKit,
        .userFonts,
        .carPlayMaps,
        .carPlayAudio,
        .appAttest,
        .dataProtection,
        .vpn,
        .networkExtensions,
        .siri,
        .applePay,
        .multipath,
        .hotspot,
        .nfc,
        .accessWiFiInformation,
        .wirelessAccessoryConfiguration,
        .gameCenter,
        .inAppPurchase,
        .classKit,
        .autoFillCredentialProvider
    ]

    var displayName: String {
        switch self {
        case .increasedMemoryLimit:             return "Increased Memory Limit"
        case .extendedVirtualAddressing:        return "Extended Virtual Addressing"
        case .increasedDebuggingMemoryLimit:    return "Increased Debugging Memory Limit"
        case .getTaskAllow:                     return "Get-Task-Allow (JIT)"
        case .appGroups:                        return "App Groups"
        case .keychainAccessGroups:             return "Keychain Access Groups"
        case .interAppAudio:                    return "Inter-App Audio"
        case .pushNotifications:                return "Push Notifications"
        case .associatedDomains:                return "Associated Domains"
        case .appleSignIn:                      return "Sign in with Apple"
        case .iCloudServices:                   return "iCloud Services"
        case .iCloudContainerIdentifiers:       return "iCloud Containers"
        case .ubiquityKeyValueStore:            return "iCloud Key-Value Storage"
        case .healthKit:                        return "HealthKit"
        case .healthKitAccess:                  return "Clinical Health Records"
        case .homeKit:                          return "HomeKit"
        case .criticalAlerts:                   return "Critical Alerts"
        case .timeSensitiveNotifications:       return "Time-Sensitive Notifications"
        case .communicationNotifications:       return "Communication Notifications"
        case .groupSession:                     return "Group Activities / SharePlay"
        case .weatherKit:                       return "WeatherKit"
        case .userFonts:                        return "Font Installation"
        case .carPlayMaps:                      return "CarPlay Navigation"
        case .carPlayAudio:                     return "CarPlay Audio"
        case .appAttest:                        return "App Attest"
        case .dataProtection:                   return "Data Protection"
        case .vpn:                              return "Personal VPN"
        case .networkExtensions:                return "Network Extensions"
        case .siri:                             return "SiriKit"
        case .applePay:                         return "Apple Pay"
        case .multipath:                        return "Multipath TCP"
        case .hotspot:                          return "Hotspot Configuration"
        case .nfc:                              return "NFC Tag Reading"
        case .accessWiFiInformation:            return "Access Wi-Fi Information"
        case .wirelessAccessoryConfiguration:   return "Wireless Accessory"
        case .gameCenter:                       return "Game Center"
        case .inAppPurchase:                    return "In-App Purchase"
        case .classKit:                         return "ClassKit"
        case .autoFillCredentialProvider:       return "AutoFill Credential Provider"
        case .applicationIdentifier:            return "Application Identifier"
        case .teamIdentifier:                   return "Team Identifier"
        default:                                return rawValue
        }
    }

    var summary: String {
        switch self {
        case .increasedMemoryLimit:             return "Increases app memory allocation limit"
        case .extendedVirtualAddressing:        return "Enables 64-bit virtual memory address space"
        case .increasedDebuggingMemoryLimit:    return "Increases memory limit when debugging"
        case .getTaskAllow:                     return "Permits debugger attachment and dynamic JIT"
        case .appGroups:                        return "Share data containers across apps and extensions"
        case .keychainAccessGroups:             return "Share keychain credentials between apps"
        case .interAppAudio:                    return "Send real-time audio with other apps"
        case .pushNotifications:                return "Apple Push Notification service"
        case .associatedDomains:                return "Universal Links and Shared Web Credentials"
        case .appleSignIn:                      return "Authenticate users with their Apple ID"
        case .iCloudServices:                   return "CloudKit and Cloud Documents"
        case .iCloudContainerIdentifiers:       return "CloudKit container IDs"
        case .ubiquityKeyValueStore:            return "Sync preferences across user devices"
        case .healthKit:                        return "Read and write personal health data"
        case .healthKitAccess:                  return "Access FHIR medical records"
        case .homeKit:                          return "Communicate with home automation accessories"
        case .criticalAlerts:                   return "Play sounds and bypass Do Not Disturb"
        case .timeSensitiveNotifications:       return "High-priority immediate notifications"
        case .communicationNotifications:       return "Call and messaging notifications with avatar"
        case .groupSession:                     return "Synchronize experiences via FaceTime"
        case .weatherKit:                       return "Access global weather forecasts and alerts"
        case .userFonts:                        return "Install custom system-wide fonts"
        case .carPlayMaps:                      return "Turn-by-turn navigation on CarPlay"
        case .carPlayAudio:                     return "Provide audio playback on CarPlay"
        case .appAttest:                        return "Verify app integrity with server backend"
        case .dataProtection:                   return "Hardware file-level encryption"
        case .vpn:                              return "Manage custom VPN connections"
        case .networkExtensions:                return "Packet tunneling and content filters"
        case .siri:                             return "Handle custom Siri voice intents"
        case .applePay:                         return "In-app payments with Apple Pay"
        case .multipath:                        return "Combine Wi-Fi and Cellular streams"
        case .hotspot:                          return "Configure Wi-Fi networks"
        case .nfc:                              return "Read NFC tags and ISO 7816 cards"
        case .accessWiFiInformation:            return "Query connected Wi-Fi network SSID"
        case .wirelessAccessoryConfiguration:   return "Configure MFi Wi-Fi accessories"
        case .gameCenter:                       return "Achievements and leaderboards"
        case .inAppPurchase:                    return "StoreKit digital purchases"
        case .classKit:                         return "Student progress reporting for education apps"
        case .autoFillCredentialProvider:       return "Provide passwords and passkeys to system"
        case .applicationIdentifier:            return "Unique identifier for the application"
        case .teamIdentifier:                   return "Developer Team Identifier"
        default:                                return ""
        }
    }

    var valueType: EntitlementValueType {
        switch self {
        case .appGroups,
             .keychainAccessGroups,
             .associatedDomains,
             .appleSignIn,
             .iCloudServices,
             .iCloudContainerIdentifiers,
             .healthKitAccess,
             .userFonts,
             .networkExtensions,
             .applePay,
             .nfc:
            return .stringArray
        case .pushNotifications,
             .ubiquityKeyValueStore,
             .appAttest,
             .dataProtection,
             .classKit,
             .applicationIdentifier,
             .teamIdentifier:
            return .string
        default:
            return .boolean
        }
    }

    var isFreeAllowed: Bool {
        Self.freeEntitlements.contains(self)
    }

    func defaultTemplate(bundleID: String = "") -> Any {
        switch self {
        case .appGroups:                        return bundleID.isEmpty ? [String]() : ["group.\(bundleID)"]
        case .iCloudContainerIdentifiers:       return bundleID.isEmpty ? [String]() : ["iCloud.\(bundleID)"]
        case .appleSignIn:                      return ["Default"]
        case .iCloudServices:                   return ["CloudKit", "CloudDocuments"]
        case .userFonts:                        return ["app-usage"]
        case .networkExtensions:                return ["packet-tunnel-provider"]
        case .nfc:                              return ["NDEF", "TAG"]
        case .keychainAccessGroups,
             .associatedDomains,
             .healthKitAccess,
             .applePay:                         return [String]()
        case .pushNotifications,
             .appAttest,
             .classKit:                         return "development"
        case .dataProtection:                   return "NSFileProtectionComplete"
        case .ubiquityKeyValueStore:            return bundleID.isEmpty ? "" : "$(TeamIdentifierPrefix)\(bundleID)"
        case .applicationIdentifier:            return bundleID
        case .teamIdentifier:                   return ""
        default:                                return true
        }
    }
}

extension Entitlement: Identifiable {
    public var id: String { rawValue }
    public var name: String { displayName }
}

public enum EntitlementValueType: String, Codable, Sendable, CaseIterable, Identifiable {
    case boolean        = "Boolean"
    case string         = "String"
    case stringArray    = "Array"
    case number         = "Number"

    public var id: String { rawValue }
}
