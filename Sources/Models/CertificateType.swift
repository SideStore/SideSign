//
//  CertificateType.swift
//  SideSign
//
//  Created by Magesh K on 11/09/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation

public struct CertificateType: RawRepresentable, Sendable, Codable, Equatable, Hashable, CustomStringConvertible, CaseIterable {
    public let rawValue: String

    public enum Category: String, Sendable, Codable {
        case development
        case distribution
    }

    public static let development  = CertificateType(rawValue: "development")
    public static let distribution = CertificateType(rawValue: "distribution")
    public static let developerID  = CertificateType(rawValue: "developer-id")
    public static let macAppStore  = CertificateType(rawValue: "mac-appstore")

    public static let allCases: [CertificateType] = [
        .development, .distribution, .developerID, .macAppStore
    ]

    public static var freeAccountCases: [CertificateType] {
        allCases.filter { $0.isFreeAccountSupported }
    }

    public static var paidOnlyCases: [CertificateType] {
        allCases.filter { $0.isPaidOnly }
    }

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public init?(argument: String) {
        switch argument.lowercased() {
        case "development", "dev", "ios development", "apple development":
            self = .development
        case "distribution", "dist", "ios distribution", "apple distribution":
            self = .distribution
        case "developer-id", "developerid":
            self = .developerID
        case "mac-appstore", "macappstore":
            self = .macAppStore
        default:
            return nil
        }
    }

    public var isFreeAccountSupported: Bool {
        self == .development
    }

    public var isPaidOnly: Bool {
        !isFreeAccountSupported
    }

    public var category: Category {
        switch self {
        case .development:
            return .development
        case .distribution, .developerID, .macAppStore:
            return .distribution
        default:
            return .development
        }
    }

    public var displayName: String {
        switch self {
        case .development:  return "Apple Development"
        case .distribution: return "Apple Distribution"
        case .developerID:  return "Developer ID Application"
        case .macAppStore:  return "Mac App Distribution"
        default:            return rawValue.capitalized
        }
    }

    public var description: String {
        rawValue
    }

    public var submitEndpointAction: String {
        switch self {
        case .development:  return "ios/submitDevelopmentCSR.action"
        case .distribution: return "ios/submitDistributionCSR.action"
        default:            return "ios/submitDevelopmentCSR.action"
        }
    }
}
