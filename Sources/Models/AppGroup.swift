//
//  AppGroup.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation

public struct AppGroup: Sendable, Codable, Equatable, Hashable, Identifiable {
    public var id: String { identifier }
    public var identifier: String // group identifier (e.g. group.com.example.app)
    public var name: String
    public var groupID: String    // developer portal applicationGroup id

    public init(name: String, identifier: String, groupID: String) {
        self.name = name
        self.identifier = identifier
        self.groupID = groupID
    }

    enum CodingKeys: String, CodingKey {
        case name
        case identifier
        case groupID = "applicationGroup"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.name = try container.decodeIfPresent(String.self, forKey: .name) ?? ""
        self.identifier = try container.decodeIfPresent(String.self, forKey: .identifier) ?? ""
        self.groupID = try container.decodeIfPresent(String.self, forKey: .groupID) ?? ""
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(name, forKey: .name)
        try container.encode(identifier, forKey: .identifier)
        try container.encode(groupID, forKey: .groupID)
    }
}
