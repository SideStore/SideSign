//
//  Feature.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation

public struct Feature: RawRepresentable, Hashable, Codable, Sendable, ExpressibleByStringLiteral {
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

    public init?(entitlement: Entitlement) {
        switch entitlement {
        case .appGroups:                       self = .appGroups
        case .interAppAudio:                   self = .interAppAudio
        case .associatedDomains:               self = .associatedDomains
        case .dataProtection:                  self = .dataProtection
        case .siri:                            self = .siri
        case .applePay:                        self = .applePay
        case .vpn:                             self = .vpn
        case .networkExtensions:               self = .networkExtensions
        case .multipath:                       self = .multipath
        case .hotspot:                         self = .hotspot
        case .nfc:                             self = .nfc
        case .classKit:                        self = .classKit
        case .autoFillCredentialProvider:      self = .autoFillCredentialProvider
        case .accessWiFiInformation:           self = .accessWiFiInformation
        case .wirelessAccessoryConfiguration:  self = .wirelessAccessoryConfiguration
        case .increasedMemoryLimit:            self = .increasedMemoryLimit
        case .extendedVirtualAddressing:       self = .extendedVirtualAddressing
        case .increasedDebuggingMemoryLimit:   self = .increasedDebuggingMemoryLimit
        case .pushNotifications:               self = .pushNotifications
        case .gameCenter:                      self = .gameCenter
        case .inAppPurchase:                   self = .inAppPurchase
        default:
            return nil
        }
    }
}

public extension Feature {
    static let appGroups: Feature                       = "APG3427HIY"
    static let gameCenter: Feature                      = "gameCenter"
    static let inAppPurchase: Feature                   = "inAppPurchase"
    static let pushNotifications: Feature               = "push"
    static let interAppAudio: Feature                   = "IAD53UNK2F"
    static let associatedDomains: Feature               = "associatedDomains"
    static let dataProtection: Feature                  = "dataProtection"
    static let siri: Feature                            = "siri"
    static let applePay: Feature                        = "applePay"
    static let vpn: Feature                             = "vpn"
    static let networkExtensions: Feature               = "networkExtensions"
    static let multipath: Feature                       = "multipath"
    static let hotspot: Feature                         = "hotspot"
    static let nfc: Feature                             = "nfc"
    static let classKit: Feature                        = "classKit"
    static let autoFillCredentialProvider: Feature      = "autoFillCredentialProvider"
    static let accessWiFiInformation: Feature           = "accessWiFiInformation"
    static let wirelessAccessoryConfiguration: Feature  = "wirelessAccessoryConfiguration"
    static let increasedMemoryLimit: Feature            = "increasedMemoryLimit"
    static let extendedVirtualAddressing: Feature       = "extendedVirtualAddressing"
    static let increasedDebuggingMemoryLimit: Feature   = "increasedDebuggingMemoryLimit"

    static let freeFeatures: Set<Feature> = [
        .appGroups,
        .interAppAudio
    ]

    static let paidFeatures: Set<Feature> = [
        .appGroups,
        .interAppAudio,
        .gameCenter,
        .inAppPurchase,
        .pushNotifications,
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
        .increasedMemoryLimit,
        .extendedVirtualAddressing,
        .increasedDebuggingMemoryLimit
    ]
}
