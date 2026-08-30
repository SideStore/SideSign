//
//  Team.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation

public enum TeamType: Int, Sendable, Codable, Equatable, Hashable {
    case unknown      = 0
    case organization = 1
    case individual   = 2
    case free         = 3
}

public struct Team: Sendable, Codable, Equatable, Hashable, Identifiable {
    public var id: String { identifier }
    public var identifier: String
    public var name: String
    public var type: TeamType
    public var account: Account?

    public init(identifier: String, name: String, type: TeamType, account: Account? = nil) {
        self.identifier = identifier
        self.name = name
        self.type = type
        self.account = account
    }

    enum CodingKeys: String, CodingKey {
        case identifier = "teamId"
        case name
        case type
        case memberships
        case teamType
    }

    struct Membership: Decodable, Sendable {
        let name: String?
        let status: String?
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let teamId = try container.decodeIfPresent(String.self, forKey: .identifier) ?? ""
        let teamName = try container.decodeIfPresent(String.self, forKey: .name) ?? ""

        let resolvedType: TeamType
        if let directType = try? container.decodeIfPresent(TeamType.self, forKey: .teamType) {
            resolvedType = directType
        } else {
            let typeString = try container.decodeIfPresent(String.self, forKey: .type)
            let memberships = try container.decodeIfPresent([Membership].self, forKey: .memberships) ?? []

            if typeString == "Company/Organization" {
                resolvedType = .organization
            } else if typeString == "Individual" {
                if memberships.count == 1,
                   let membershipName = memberships.first?.name,
                   membershipName.lowercased().contains("free") {
                    resolvedType = .free
                } else {
                    resolvedType = .individual
                }
            } else {
                resolvedType = .unknown
            }
        }

        self.init(
            identifier: teamId,
            name: teamName,
            type: resolvedType,
            account: nil
        )
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(identifier, forKey: .identifier)
        try container.encode(name, forKey: .name)
        try container.encode(type, forKey: .teamType)
    }
}
