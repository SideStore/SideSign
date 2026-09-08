//
//  ProvisioningProfile.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
import CodeSignKit

public struct ProvisioningProfile: Sendable, Codable, Equatable, Hashable, Identifiable {
    public var id: String { uuid.uuidString }
    public var identifier: String? // provisioningProfileId from Apple Developer Portal
    public var name: String
    public var uuid: UUID
    public var bundleIdentifier: String
    public var teamIdentifier: String
    public var teamName: String
    public var creationDate: Date
    public var expirationDate: Date
    public var deviceIDs: [String]
    public var isFreeProvisioningProfile: Bool
    public var data: Data

    public var entitlements: [String: any Sendable] {
        guard let dict = try? Self.dictionary(fromEncodedData: data),
              let ents = dict["Entitlements"] as? [String: any Sendable] else 
        {
            return [:]
        }
        return ents
    }

    public var certificates: [X509Certificate] {
        guard let dict = try? Self.dictionary(fromEncodedData: data),
              let certDatas = dict["DeveloperCertificates"] as? [Data] else 
        {
            return []
        }
        return certDatas.compactMap { X509Certificate(data: $0) }
    }

    public init(name: String,
                uuid: UUID,
                bundleIdentifier: String,
                teamIdentifier: String,
                teamName: String,
                creationDate: Date,
                expirationDate: Date,
                deviceIDs: [String] = [],
                isFreeProvisioningProfile: Bool = false,
                data: Data,
                identifier: String? = nil)
    {
        self.name = name
        self.uuid = uuid
        self.bundleIdentifier = bundleIdentifier
        self.teamIdentifier = teamIdentifier
        self.teamName = teamName
        self.creationDate = creationDate
        self.expirationDate = expirationDate
        self.deviceIDs = deviceIDs
        self.isFreeProvisioningProfile = isFreeProvisioningProfile
        self.data = data
        self.identifier = identifier
    }

    public init(data: Data) throws {
        let dict = try Self.dictionary(fromEncodedData: data)

        let name: String = try Self.require("Name", from: dict)
        let uuidString: String = try Self.require("UUID", from: dict)
        guard let uuid = Foundation.UUID(uuidString: uuidString) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(codingPath: [], debugDescription: "Invalid UUID format for '\(uuidString)'")
            )
        }

        let teamIdentifiers: [String] = try Self.require("TeamIdentifier", from: dict)
        guard let teamIdentifier = teamIdentifiers.first else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(codingPath: [], debugDescription: "'TeamIdentifier' array is empty")
            )
        }

        let teamName: String = try Self.require("TeamName", from: dict)
        let creationDate: Date = try Self.require("CreationDate", from: dict)
        let expirationDate: Date = try Self.require("ExpirationDate", from: dict)
        let entitlementsRaw: [String: any Sendable] = try Self.require("Entitlements", from: dict)

        var bundleID: String?
        if let appID = entitlementsRaw["application-identifier"] as? String,
           let dot = appID.firstIndex(of: ".") {
            bundleID = String(appID[appID.index(after: dot)...])
        }

        guard let resolvedBundleID = bundleID else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(codingPath: [], debugDescription: "Missing or invalid 'application-identifier' in Entitlements")
            )
        }

        self.data = data
        self.name = name
        self.uuid = uuid
        self.bundleIdentifier = resolvedBundleID
        self.teamIdentifier = teamIdentifier
        self.teamName = teamName
        self.creationDate = creationDate
        self.expirationDate = expirationDate
        self.deviceIDs = (dict["ProvisionedDevices"] as? [String]) ?? []
        self.isFreeProvisioningProfile = (dict["LocalProvision"] as? Bool) ?? false
        self.identifier = nil
    }

    private static func require<T>(_ key: String, from dict: [String: any Sendable]) throws -> T {
        guard let raw = dict[key] else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(codingPath: [], debugDescription: "Missing required key '\(key)'")
            )
        }
        guard let val = raw as? T else {
            throw DecodingError.typeMismatch(
                T.self,
                DecodingError.Context(codingPath: [], debugDescription: "Expected key '\(key)' to be of type \(T.self), but found \(type(of: raw))")
            )
        }
        return val
    }

    public init(url: URL) throws {
        let data = try Data(contentsOf: url)
        try self.init(data: data)
    }

    public init(fileURL: URL) throws {
        try self.init(url: fileURL)
    }

    enum CodingKeys: String, CodingKey {
        case identifier
        case name
        case uuid
        case bundleIdentifier
        case teamIdentifier
        case teamName
        case creationDate
        case expirationDate
        case deviceIDs
        case isFreeProvisioningProfile
        case data
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        let name = try container.decode(String.self, forKey: .name)
        let uuidString = try container.decode(String.self, forKey: .uuid)
        guard let uuid = Foundation.UUID(uuidString: uuidString) else {
            throw DecodingError.dataCorruptedError(forKey: .uuid, in: container, debugDescription: "Invalid UUID string: \(uuidString)")
        }
        let bundleID = try container.decode(String.self, forKey: .bundleIdentifier)
        let teamID = try container.decode(String.self, forKey: .teamIdentifier)
        let teamName = try container.decode(String.self, forKey: .teamName)
        let created = try container.decode(Date.self, forKey: .creationDate)
        let expires = try container.decode(Date.self, forKey: .expirationDate)
        let devices = try container.decodeIfPresent([String].self, forKey: .deviceIDs) ?? []
        let isFree = try container.decodeIfPresent(Bool.self, forKey: .isFreeProvisioningProfile) ?? false
        let data = try container.decode(Data.self, forKey: .data)
        let identifier = try container.decodeIfPresent(String.self, forKey: .identifier)

        self.init(
            name: name,
            uuid: uuid,
            bundleIdentifier: bundleID,
            teamIdentifier: teamID,
            teamName: teamName,
            creationDate: created,
            expirationDate: expires,
            deviceIDs: devices,
            isFreeProvisioningProfile: isFree,
            data: data,
            identifier: identifier
        )
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(name, forKey: .name)
        try container.encode(uuid.uuidString, forKey: .uuid)
        try container.encode(bundleIdentifier, forKey: .bundleIdentifier)
        try container.encode(teamIdentifier, forKey: .teamIdentifier)
        try container.encode(teamName, forKey: .teamName)
        try container.encode(creationDate, forKey: .creationDate)
        try container.encode(expirationDate, forKey: .expirationDate)
        try container.encode(deviceIDs, forKey: .deviceIDs)
        try container.encode(isFreeProvisioningProfile, forKey: .isFreeProvisioningProfile)
        try container.encode(data, forKey: .data)
        try container.encodeIfPresent(identifier, forKey: .identifier)
    }

    private static func dictionary(fromEncodedData data: Data) throws -> [String: any Sendable] {
        let string = String(decoding: data, as: UTF8.self)
        let scanner = Scanner(string: string)

        guard scanner.scanUpToString("<?xml") != nil,
              let plistString = scanner.scanUpToString("</plist>"),
              let plistData = (plistString + "</plist>").data(using: .utf8)
        else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(codingPath: [], debugDescription: "Could not find '<?xml' ... '</plist>' boundary in provisioning profile CMS data (\(data.count) bytes)")
            )
        }

        let raw = try PropertyListSerialization.propertyList(from: plistData, options: [], format: nil)
        guard let dict = raw as? [String: any Sendable] else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(codingPath: [], debugDescription: "Provisioning profile XML root is not a dictionary")
            )
        }
        return dict
    }
}
