//
//  Account.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation

public struct Account: Sendable, Codable, Equatable, Hashable, Identifiable {
    public var id: String { identifier }
    public var identifier: String
    public var appleID: String
    public var firstName: String
    public var lastName: String

    public var name: String {
        #if canImport(Darwin)
        var components = PersonNameComponents()
        components.givenName = firstName
        components.familyName = lastName
        return PersonNameComponentsFormatter.localizedString(
            from: components,
            style: .default,
            options: []
        )
        #else
        return [firstName, lastName].filter { !$0.isEmpty }.joined(separator: " ")
        #endif
    }

    public init(appleID: String, identifier: String, firstName: String = "", lastName: String = "") {
        self.appleID = appleID
        self.identifier = identifier
        self.firstName = firstName
        self.lastName = lastName
    }
}
