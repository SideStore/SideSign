//
//  Session.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation

public struct Session: Sendable, Codable, Equatable, Hashable {
    public var dsid: String
    public var authToken: String
    public var anisetteData: AnisetteData
    public var xcodeVersion: String
    public var machinePassword: String?
    public var creationDate: Date?
    public var expirationDate: Date?
    public var timeToLive: TimeInterval?

    public var isValid: Bool {
        guard let expirationDate = expirationDate else { return true }
        return Date() < expirationDate
    }

    public var isExpired: Bool {
        !isValid
    }

    public init(
        dsid: String,
        authToken: String,
        anisetteData: AnisetteData,
        xcodeVersion: String,
        machinePassword: String? = nil,
        creationDate: Date? = nil,
        expirationDate: Date? = nil,
        timeToLive: TimeInterval? = nil
    ) {
        self.dsid = dsid
        self.authToken = authToken
        self.anisetteData = anisetteData
        self.xcodeVersion = xcodeVersion
        self.machinePassword = machinePassword
        self.creationDate = creationDate
        self.expirationDate = expirationDate
        self.timeToLive = timeToLive
    }
}
