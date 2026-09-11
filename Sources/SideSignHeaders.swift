//
//  SideSignHeaders.swift
//  SideSign
//
//  Created by Magesh K on 11/9/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation

public struct SideSignHeaders: Codable, Sendable, Equatable {
    public var grandSlam: GrandSlam
    public var appleAuth: AppleAuth
    public var developerServices: DeveloperServices

    public init(
        grandSlam: GrandSlam = GrandSlam(),
        appleAuth: AppleAuth = AppleAuth(),
        developerServices: DeveloperServices = DeveloperServices()
    ) {
        self.grandSlam = grandSlam
        self.appleAuth = appleAuth
        self.developerServices = developerServices
    }

    public struct GrandSlam: Codable, Sendable, Equatable {
        public var service: String
        public var headerVersion: String
        public var authApp: String
        public var userAgent: String

        public init(
            service: String = Constants.GrandSlam.service,
            headerVersion: String = Constants.GrandSlam.headerVersion,
            authApp: String = Constants.GrandSlam.authApp,
            userAgent: String = Constants.GrandSlam.userAgent
        ) {
            self.service = service
            self.headerVersion = headerVersion
            self.authApp = authApp
            self.userAgent = userAgent
        }
    }

    public struct AppleAuth: Codable, Sendable, Equatable {
        public var appIDKey: String
        public var userAgent: String

        public init(
            appIDKey: String = Constants.AppleAuth.appIDKey,
            userAgent: String = Constants.AppleAuth.userAgent
        ) {
            self.appIDKey = appIDKey
            self.userAgent = userAgent
        }
    }

    public struct DeveloperServices: Codable, Sendable, Equatable {
        public var clientID: String
        public var protocolVersion: String
        public var servicesProtocolVersion: String
        public var userAgent: String

        public init(
            clientID: String = Constants.DeveloperServices.clientID,
            protocolVersion: String = Constants.DeveloperServices.protocolVersion,
            servicesProtocolVersion: String = Constants.DeveloperServices.servicesProtocolVersion,
            userAgent: String = Constants.DeveloperServices.userAgent
        ) {
            self.clientID = clientID
            self.protocolVersion = protocolVersion
            self.servicesProtocolVersion = servicesProtocolVersion
            self.userAgent = userAgent
        }
    }
}
