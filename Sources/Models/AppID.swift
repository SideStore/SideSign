//
//  AppID.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation

public struct AppID: Sendable, Codable, Identifiable {
    public var id: String { identifier }
    public var identifier: String // appIdId (e.g. 10 character id)
    public var name: String
    public var bundleIdentifier: String
    public var expirationDate: Date?
    public var features: [Feature: String]
    public var entitlements: [String: String]

    public init(identifier: String,
                name: String,
                bundleIdentifier: String,
                expirationDate: Date? = nil,
                features: [Feature: String] = [:],
                entitlements: [String: String] = [:])
    {
        self.identifier = identifier
        self.name = name
        self.bundleIdentifier = bundleIdentifier
        self.expirationDate = expirationDate
        self.features = features
        self.entitlements = entitlements
    }

    public func copy() -> AppID {
        self
    }

    enum CodingKeys: String, CodingKey {
        case name
        case identifier = "appIdId"
        case bundleIdentifier = "identifier"
        case expirationDate
        case features
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.name = try container.decodeIfPresent(String.self, forKey: .name) ?? ""
        self.identifier = try container.decodeIfPresent(String.self, forKey: .identifier) ?? ""
        self.bundleIdentifier = try container.decodeIfPresent(String.self, forKey: .bundleIdentifier) ?? ""
        self.expirationDate = try container.decodeIfPresent(Date.self, forKey: .expirationDate)

        if let featMap = try? container.decodeIfPresent([String: String].self, forKey: .features) {
            self.features = featMap.reduce(into: [:]) { $0[Feature(rawValue: $1.key)] = $1.value }
        } else if let boolMap = try? container.decodeIfPresent([String: Bool].self, forKey: .features) {
            self.features = boolMap.reduce(into: [:]) { $0[Feature(rawValue: $1.key)] = $1.value ? "true" : "false" }
        } else {
            self.features = [:]
        }
        self.entitlements = [:]
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(name, forKey: .name)
        try container.encode(identifier, forKey: .identifier)
        try container.encode(bundleIdentifier, forKey: .bundleIdentifier)
        try container.encodeIfPresent(expirationDate, forKey: .expirationDate)
    }
}
