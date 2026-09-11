//
//  ProfileType.swift
//  SideSign
//
//  Created by Magesh K on 11/09/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation

public struct ProfileType: RawRepresentable, Sendable, Codable, Equatable, Hashable, CustomStringConvertible, CaseIterable {
    public let rawValue: String

    public enum Category: String, Sendable, Codable {
        case development
        case distribution
    }

    public typealias ManagementStyle = ProfileManagementStyle

    // Development (Free & Paid)
    public static let iOS              = ProfileType(rawValue: "ios")
    public static let tvOS             = ProfileType(rawValue: "tvos")
    public static let macOS            = ProfileType(rawValue: "mac")
    public static let visionOS         = ProfileType(rawValue: "visionos")
    // Development (Paid Only)
    public static let driverKit        = ProfileType(rawValue: "driverkit")

    // Distribution (Paid Only)
    public static let adHoc            = ProfileType(rawValue: "adhoc")
    public static let tvOSAdHoc        = ProfileType(rawValue: "tvos-adhoc")
    public static let appStore         = ProfileType(rawValue: "appstore")
    public static let tvOSAppStore     = ProfileType(rawValue: "tvos-appstore")
    public static let macAppStore      = ProfileType(rawValue: "mac-appstore")
    public static let developerID      = ProfileType(rawValue: "developer-id")

    public static let allCases: [ProfileType] = [
        .iOS, .tvOS, .macOS, .visionOS, .driverKit,
        .adHoc, .tvOSAdHoc, .appStore, .tvOSAppStore, .macAppStore, .developerID
    ]

    /// Profiles supported by Free accounts
    public static var freeAccountCases: [ProfileType] {
        allCases.filter { $0.isFreeAccountSupported }
    }

    /// Profiles supported exclusively by Paid accounts
    public static var paidOnlyCases: [ProfileType] {
        allCases.filter { $0.isPaidOnly }
    }

    public init(rawValue: String) {
        switch rawValue.lowercased() {
        case "ios", "iphone", "ipad":
            self.rawValue = "ios"
        case "tvos", "appletv", "tv":
            self.rawValue = "tvos"
        case "macos", "mac", "osx":
            self.rawValue = "mac"
        case "visionos", "xr", "visionpro", "vision":
            self.rawValue = "visionos"
        case "driverkit":
            self.rawValue = "driverkit"
        case "adhoc", "ios-adhoc":
            self.rawValue = "adhoc"
        case "tvos-adhoc":
            self.rawValue = "tvos-adhoc"
        case "appstore", "ios-appstore", "store":
            self.rawValue = "appstore"
        case "tvos-appstore":
            self.rawValue = "tvos-appstore"
        case "mac-appstore":
            self.rawValue = "mac-appstore"
        case "developer-id", "developerid":
            self.rawValue = "developer-id"
        default:
            self.rawValue = rawValue.lowercased()
        }
    }

    public init?(argument: String) {
        switch argument.lowercased() {
        case "ios", "iphone", "ipad":
            self = .iOS
        case "tvos", "appletv", "tv":
            self = .tvOS
        case "macos", "mac", "osx":
            self = .macOS
        case "visionos", "xr", "visionpro", "vision":
            self = .visionOS
        case "driverkit":
            self = .driverKit
        case "adhoc", "ios-adhoc":
            self = .adHoc
        case "tvos-adhoc":
            self = .tvOSAdHoc
        case "appstore", "ios-appstore", "store":
            self = .appStore
        case "tvos-appstore":
            self = .tvOSAppStore
        case "mac-appstore":
            self = .macAppStore
        case "developer-id", "developerid":
            self = .developerID
        default:
            return nil
        }
    }

    public var isFreeAccountSupported: Bool {
        switch self {
        case .iOS, .tvOS, .macOS, .visionOS:
            return true
        default:
            return false
        }
    }

    public var isPaidOnly: Bool {
        !isFreeAccountSupported
    }

    public var category: Category {
        switch self {
        case .iOS, .tvOS, .macOS, .visionOS, .driverKit:
            return .development
        case .adHoc, .tvOSAdHoc, .appStore, .tvOSAppStore, .macAppStore, .developerID:
            return .distribution
        default:
            return .development
        }
    }

    public var displayName: String {
        switch self {
        case .iOS:          return "iOS App Development (ios)"
        case .tvOS:         return "tvOS App Development (tvos)"
        case .macOS:        return "macOS App Development (mac)"
        case .visionOS:     return "visionOS App Development (visionos)"
        case .driverKit:    return "DriverKit App Development (driverkit)"
        case .adHoc:        return "Ad Hoc (adhoc)"
        case .tvOSAdHoc:    return "tvOS Ad Hoc (tvos-adhoc)"
        case .appStore:     return "App Store Connect (appstore)"
        case .tvOSAppStore: return "tvOS App Store Connect (tvos-appstore)"
        case .macAppStore:  return "Mac App Store Connect (mac-appstore)"
        case .developerID:  return "Developer ID (developer-id)"
        default:            return rawValue
        }
    }

    public var acceptedDeviceTypes: DeviceType {
        switch self {
        case .iOS, .adHoc:
            return [.iPhone, .iPad]
        case .tvOS, .tvOSAdHoc:
            return [.appleTV]
        case .macOS, .driverKit:
            return [.mac]
        case .visionOS:
            return [.visionPro]
        case .appStore, .tvOSAppStore, .macAppStore, .developerID:
            return .none
        default:
            return .none
        }
    }

    public var primaryDeviceType: DeviceType {
        switch self {
        case .iOS, .adHoc, .appStore:
            return .iPhone
        case .tvOS, .tvOSAdHoc, .tvOSAppStore:
            return .appleTV
        case .macOS, .macAppStore, .developerID, .driverKit:
            return .mac
        case .visionOS:
            return .visionPro
        default:
            return .iPhone
        }
    }

    public var subPlatformParameter: String? {
        switch self {
        case .iOS, .adHoc, .appStore:
            return nil
        case .tvOS, .tvOSAdHoc, .tvOSAppStore:
            return "tvOS"
        case .macOS, .macAppStore, .developerID, .driverKit:
            return "macOS"
        case .visionOS:
            return "visionOS"
        default:
            return nil
        }
    }

    public var distributionTypeParameter: String {
        switch self {
        case .iOS, .tvOS, .macOS, .visionOS, .driverKit:
            return "limited"
        case .adHoc, .tvOSAdHoc:
            return "adhoc"
        case .appStore, .tvOSAppStore, .macAppStore:
            return "store"
        case .developerID:
            return "developer-id"
        default:
            return "limited"
        }
    }

    public var description: String { displayName }
}

public enum ProfileManagementStyle: String, Sendable, Codable, CaseIterable {
    case manual
    case xcodeManaged

    public init?(argument: String) {
        switch argument.lowercased() {
        case "manual":
            self = .manual
        case "xcode", "xcodemanaged", "xcode-managed":
            self = .xcodeManaged
        default:
            return nil
        }
    }
}
