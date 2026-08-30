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

    public init(
        dsid: String,
        authToken: String,
        anisetteData: AnisetteData,
        xcodeVersion: String
    ) {
        self.dsid = dsid
        self.authToken = authToken
        self.anisetteData = anisetteData
        self.xcodeVersion = xcodeVersion
    }
}
