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

    static let freeEntitlements: Set<Entitlement> = [
        .appGroups,
        .interAppAudio,
        .getTaskAllow,
        .increasedMemoryLimit,
        .increasedDebuggingMemoryLimit,
        .extendedVirtualAddressing,
        .teamIdentifier,
        .keychainAccessGroups,
        .applicationIdentifier
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
        .inAppPurchase
    ]
}
