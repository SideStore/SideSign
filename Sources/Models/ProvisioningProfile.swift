//
//  ProvisioningProfile.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation

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
        guard let dict = Self.dictionary(fromEncodedData: data),
              let ents = dict["Entitlements"] as? [String: any Sendable] else 
        {
            return [:]
        }
        return ents
    }

    public var certificates: [X509Certificate] {
        guard let dict = Self.dictionary(fromEncodedData: data),
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

    public init?(data: Data) {
        guard let dict = Self.dictionary(fromEncodedData: data),
              let name = dict["Name"] as? String,
              let uuidString = dict["UUID"] as? String,
              let uuid = Foundation.UUID(uuidString: uuidString),
              let teamIdentifier = (dict["TeamIdentifier"] as? [String])?.first,
              let teamName = dict["TeamName"] as? String,
              let creationDate = dict["CreationDate"] as? Date,
              let expirationDate = dict["ExpirationDate"] as? Date,
              let entitlementsRaw = dict["Entitlements"] as? [String: any Sendable]
        else {
            return nil
        }

        var bundleID: String?
        if let appID = entitlementsRaw["application-identifier"] as? String,
           let dot = appID.firstIndex(of: ".") {
            bundleID = String(appID[appID.index(after: dot)...])
        }

        guard let resolvedBundleID = bundleID else { return nil }

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

    public init?(url: URL) {
        guard let data = try? Data(contentsOf: url) else { return nil }
        self.init(data: data)
    }

    public init?(fileURL: URL) {
        self.init(url: fileURL)
    }

    enum CodingKeys: String, CodingKey {
        case encodedProfile
        case provisioningProfileId
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
        case identifier
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if let encodedData = try? container.decodeIfPresent(Data.self, forKey: .encodedProfile),
           let profile = ProvisioningProfile(data: encodedData) {
            var mutable = profile
            mutable.identifier = try? container.decodeIfPresent(String.self, forKey: .provisioningProfileId)
            self = mutable
            return
        }

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

    private static func dictionary(fromEncodedData data: Data) -> [String: any Sendable]? {
        let string = String(decoding: data, as: UTF8.self)
        let scanner = Scanner(string: string)

        guard scanner.scanUpToString("<?xml") != nil,
              let plistString = scanner.scanUpToString("</plist>"),
              let plistData = (plistString + "</plist>").data(using: .utf8)
        else {
            return nil
        }

        return try? PropertyListSerialization.propertyList(
            from: plistData,
            options: [],
            format: nil
        ) as? [String: any Sendable]
    }
}
