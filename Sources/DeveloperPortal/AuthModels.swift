//
//  AuthModels.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation

public struct ClientPayload: Sendable, Codable, Equatable {
    public var bootstrap: Bool
    public var icscrec: Bool
    public var pbe: Bool
    public var prkgen: Bool
    public var svct: String
    public var loc: String
    public var pbkdf2: Bool

    public init(loc: String) {
        self.bootstrap = true
        self.icscrec = true
        self.pbe = false
        self.prkgen = true
        self.svct = "iCloud"
        self.loc = loc
        self.pbkdf2 = true
    }
}

public struct SRPInitRequest: Sendable, Codable, Equatable {
    public var a: Data
    public var cpd: ClientPayload
    public var o: String
    public var ps: [String]
    public var u: String

    public init(publicKey: Data, clientPayload: ClientPayload, username: String) {
        self.a = publicKey
        self.cpd = clientPayload
        self.o = "init"
        self.ps = ["s2k", "s2k_fo"]
        self.u = username
    }
}

public struct SRPCompleteRequest: Sendable, Codable, Equatable {
    public var c: String?
    public var cpd: ClientPayload
    public var m1: Data
    public var o: String
    public var u: String

    public init(challenge: String?, clientPayload: ClientPayload, verificationMessage: Data, username: String) {
        self.c = challenge
        self.cpd = clientPayload
        self.m1 = verificationMessage
        self.o = "complete"
        self.u = username
    }
}

public struct AppTokensRequest: Sendable, Codable, Equatable {
    public var app: [String]
    public var c: Data
    public var checksum: Data
    public var cpd: ClientPayload
    public var o: String
    public var t: String
    public var u: String

    public init(app: String, c: Data, checksum: Data, clientPayload: ClientPayload, token: String, dsid: String) {
        self.app = [app]
        self.c = c
        self.checksum = checksum
        self.cpd = clientPayload
        self.o = "apptokens"
        self.t = token
        self.u = dsid
    }
}

public struct GrandSlamStatus: Sendable, Codable, Equatable {
    public var ec: Int?
    public var em: String?

    public init(ec: Int? = nil, em: String? = nil) {
        self.ec = ec
        self.em = em
    }
}

public struct GrandSlamAuthResponse: Sendable, Codable, Equatable {
    public var status: GrandSlamStatus?
    public var s: Data?
    public var b: Data?
    public var i: Int?
    public var sp: String?
    public var c: String?
    public var spd: Data?
    public var m2: Data?
    public var au: String?

    enum CodingKeys: String, CodingKey {
        case status = "Status"
        case s
        case b
        case i
        case sp
        case c
        case spd
        case m2
        case au
    }
}

public struct AssignAppGroupsRequest: Sendable, Codable, Equatable {
    public var appIdId: String
    public var applicationGroups: [String]

    public init(appIdId: String, applicationGroups: [String]) {
        self.appIdId = appIdId
        self.applicationGroups = applicationGroups
    }
}
