//
//  Device.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation

public struct DeviceType: OptionSet, Sendable, Codable, Equatable, Hashable {
    public let rawValue: Int

    public static let iPhone  = DeviceType(rawValue: 1 << 1)
    public static let iPad    = DeviceType(rawValue: 1 << 2)
    public static let appleTV = DeviceType(rawValue: 1 << 3)

    public static let none: DeviceType = []
    public static let all: DeviceType = [.iPhone, .iPad, .appleTV]

    public init(rawValue: Int) {
        self.rawValue = rawValue
    }
}

public struct Device: Sendable, Codable, Equatable, Hashable, Identifiable {
    public var id: String { identifier }
    public var name: String
    public var identifier: String // UDID
    public var type: DeviceType
    public var osVersion: OperatingSystemVersion?

    public init(name: String, identifier: String, type: DeviceType, osVersion: OperatingSystemVersion? = nil) {
        self.name = name
        self.identifier = identifier
        self.type = type
        self.osVersion = osVersion
    }

    enum CodingKeys: String, CodingKey {
        case name
        case identifier = "deviceNumber"
        case deviceClass
        case type
        case osVersion
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.name = try container.decodeIfPresent(String.self, forKey: .name) ?? ""
        self.identifier = try container.decodeIfPresent(String.self, forKey: .identifier) ?? ""

        if let directType = try? container.decodeIfPresent(DeviceType.self, forKey: .type) {
            self.type = directType
        } else {
            let deviceClass = (try? container.decodeIfPresent(String.self, forKey: .deviceClass)) ?? "iphone"
            switch deviceClass {
            case "iphone": self.type = .iPhone
            case "ipad":   self.type = .iPad
            case "tvOS":   self.type = .appleTV
            default:       self.type = .none
            }
        }
        self.osVersion = try? container.decodeIfPresent(OperatingSystemVersion.self, forKey: .osVersion)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(name, forKey: .name)
        try container.encode(identifier, forKey: .identifier)
        try container.encode(type, forKey: .type)
        try container.encodeIfPresent(osVersion, forKey: .osVersion)
    }
}

extension OperatingSystemVersion: @retroactive Equatable, @retroactive Hashable, @retroactive Codable, @retroactive Comparable, @retroactive LosslessStringConvertible, @retroactive CustomStringConvertible {
    public static func == (lhs: OperatingSystemVersion, rhs: OperatingSystemVersion) -> Bool {
        lhs.majorVersion == rhs.majorVersion &&
        lhs.minorVersion == rhs.minorVersion &&
        lhs.patchVersion == rhs.patchVersion
    }

    public static func < (lhs: OperatingSystemVersion, rhs: OperatingSystemVersion) -> Bool {
        if lhs.majorVersion != rhs.majorVersion {
            return lhs.majorVersion < rhs.majorVersion
        }
        if lhs.minorVersion != rhs.minorVersion {
            return lhs.minorVersion < rhs.minorVersion
        }
        return lhs.patchVersion < rhs.patchVersion
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(majorVersion)
        hasher.combine(minorVersion)
        hasher.combine(patchVersion)
    }

    public init?(_ description: String) {
        self.init(string: description)
    }

    public init?(string: String) {
        let parts = string.split(separator: ".").compactMap { Int($0) }
        guard !parts.isEmpty else { return nil }
        self.init(
            majorVersion: parts.indices.contains(0) ? parts[0] : 0,
            minorVersion: parts.indices.contains(1) ? parts[1] : 0,
            patchVersion: parts.indices.contains(2) ? parts[2] : 0
        )
    }

    public var description: String {
        "\(majorVersion).\(minorVersion).\(patchVersion)"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let str = try container.decode(String.self)
        let parts = str.split(separator: ".").compactMap { Int($0) }
        self.init(
            majorVersion: parts.indices.contains(0) ? parts[0] : 0,
            minorVersion: parts.indices.contains(1) ? parts[1] : 0,
            patchVersion: parts.indices.contains(2) ? parts[2] : 0
        )
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        let str = "\(majorVersion).\(minorVersion).\(patchVersion)"
        try container.encode(str)
    }
}
