//
//  CommandContext.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideStore. All rights reserved.
//

import Foundation

public enum CLIError: Error, LocalizedError {
    case missingRequiredArgument(String)
    case invalidArgument(String)
    case executionFailed(String)

    public var errorDescription: String? {
        switch self {
        case .missingRequiredArgument(let msg): return msg
        case .invalidArgument(let msg):         return msg
        case .executionFailed(let msg):         return msg
        }
    }
}

public struct SignContext: Sendable {
    public let targetPath: String
    public let p12Path: String
    public let password: String
    public let profilePath: String?
    public let bundleID: String?
    public let teamID: String?
    public let entitlementsPath: String?
    public let outputPath: String?

    public init(
        targetPath: String,
        p12Path: String,
        password: String = "",
        profilePath: String? = nil,
        bundleID: String? = nil,
        teamID: String? = nil,
        entitlementsPath: String? = nil,
        outputPath: String? = nil
    ) {
        self.targetPath = targetPath
        self.p12Path = p12Path
        self.password = password
        self.profilePath = profilePath
        self.bundleID = bundleID
        self.teamID = teamID
        self.entitlementsPath = entitlementsPath
        self.outputPath = outputPath
    }
}

public struct VerifyContext: Sendable {
    public let targetPath: String
    public let isDeep: Bool
    public let isStrict: Bool

    public init(targetPath: String, isDeep: Bool = false, isStrict: Bool = false) {
        self.targetPath = targetPath
        self.isDeep = isDeep
        self.isStrict = isStrict
    }
}

public struct InspectContext: Sendable {
    public let targetPath: String
    public let dumpEntitlements: Bool
    public let dumpRequirements: Bool

    public init(targetPath: String, dumpEntitlements: Bool = false, dumpRequirements: Bool = false) {
        self.targetPath = targetPath
        self.dumpEntitlements = dumpEntitlements
        self.dumpRequirements = dumpRequirements
    }
}

public struct ProfileContext: Sendable {
    public enum Action: Sendable {
        case dump
        case validate
    }

    public let action: Action
    public let profilePath: String

    public init(action: Action, profilePath: String) {
        self.action = action
        self.profilePath = profilePath
    }
}

public struct ExtensionsContext: Sendable {
    public enum Action: Sendable {
        case list
        case remove(all: Bool, targetID: String?, outputPath: String?)
    }

    public let targetPath: String
    public let action: Action

    public init(targetPath: String, action: Action) {
        self.targetPath = targetPath
        self.action = action
    }
}

public struct ArchiveContext: Sendable {
    public enum Action: Sendable {
        case unzip(inputPath: String, outputPath: String?)
        case zip(inputPath: String, outputPath: String?)
    }

    public let action: Action

    public init(action: Action) {
        self.action = action
    }
}

public struct RemoveSignatureContext: Sendable {
    public let targetPath: String

    public init(targetPath: String) {
        self.targetPath = targetPath
    }
}

public struct P12Context: Sendable {
    public enum Action: Sendable {
        case create(certPath: String, keyPath: String, password: String?, outputPath: String)
        case extract(inputPath: String, password: String?, outCertPath: String, outKeyPath: String)
    }

    public let action: Action

    public init(action: Action) {
        self.action = action
    }
}

public struct CSRContext: Sendable {
    public let commonName: String
    public let organization: String
    public let country: String
    public let state: String
    public let locality: String
    public let outputCSR: String
    public let outputKey: String

    public init(
        commonName: String = "SideSign",
        organization: String = "SideSign",
        country: String = "US",
        state: String = "CA",
        locality: String = "Los Angeles",
        outputCSR: String,
        outputKey: String
    ) {
        self.commonName = commonName
        self.organization = organization
        self.country = country
        self.state = state
        self.locality = locality
        self.outputCSR = outputCSR
        self.outputKey = outputKey
    }
}

public struct AnisetteContext: Sendable {
    public enum Action: Sendable {
        case listServers(sourceURL: String)
        case generate(
            serverURL: String?,
            localDir: String?,
            odaURL: String?,
            sourceURLStr: String?,
            anisetteDeviceUDID: String?,
            deviceDataPath: String?,
            deviceDataPassword: String?,
            teamID: String?,
            selectServer: Bool,
            enableFailover: Bool,
            startIndex: Int,
            asJSON: Bool,
            strict: Bool
        )
    }

    public let action: Action

    public init(action: Action) {
        self.action = action
    }
}

public struct PortalOptions: Sendable {
    public let sessionPath: String?
    public let password: String?
    public let encryptPassword: String?
    public let deviceDataPath: String?
    public let deviceDataPassword: String?
    public let teamID: String?
    public let anisetteURL: String?
    public let localAnisetteDir: String?
    public let odaURL: String?
    public let selectServer: Bool
    public let strict: Bool
    public let sourceURLStr: String?
    public let enableFailover: Bool
    public let startIndex: Int

    public init(
        sessionPath: String? = nil,
        password: String? = nil,
        encryptPassword: String? = nil,
        deviceDataPath: String? = nil,
        deviceDataPassword: String? = nil,
        teamID: String? = nil,
        anisetteURL: String? = nil,
        localAnisetteDir: String? = nil,
        odaURL: String? = nil,
        selectServer: Bool = false,
        strict: Bool = false,
        sourceURLStr: String? = nil,
        enableFailover: Bool = false,
        startIndex: Int = 0
    ) {
        self.sessionPath = sessionPath
        self.password = password
        self.encryptPassword = encryptPassword
        self.deviceDataPath = deviceDataPath
        self.deviceDataPassword = deviceDataPassword
        self.teamID = teamID
        self.anisetteURL = anisetteURL
        self.localAnisetteDir = localAnisetteDir
        self.odaURL = odaURL
        self.selectServer = selectServer
        self.strict = strict
        self.sourceURLStr = sourceURLStr
        self.enableFailover = enableFailover
        self.startIndex = startIndex
    }
}

public struct PortalLoginOptions: Sendable {
    public let appleID: String
    public let portalOptions: PortalOptions

    public init(appleID: String, portalOptions: PortalOptions) {
        self.appleID = appleID
        self.portalOptions = portalOptions
    }
}

public struct PortalDeviceOptions: Sendable {
    public enum Action: Sendable {
        case list
        case register(name: String, udid: String)
        case update(name: String, udid: String)
        case disable(udid: String)
        case delete(udid: String)
    }

    public let action: Action
    public let portalOptions: PortalOptions

    public init(action: Action, portalOptions: PortalOptions) {
        self.action = action
        self.portalOptions = portalOptions
    }
}

public struct PortalCertOptions: Sendable {
    public enum Action: Sendable {
        case list
        case create(csrPath: String?, outPath: String?)
        case revoke(certID: String)
    }

    public let action: Action
    public let portalOptions: PortalOptions

    public init(action: Action, portalOptions: PortalOptions) {
        self.action = action
        self.portalOptions = portalOptions
    }
}

public struct PortalAppIDOptions: Sendable {
    public enum Action: Sendable {
        case list
        case register(name: String, bundleID: String)
        case delete(targetID: String)
    }

    public let action: Action
    public let portalOptions: PortalOptions

    public init(action: Action, portalOptions: PortalOptions) {
        self.action = action
        self.portalOptions = portalOptions
    }
}

public struct PortalAppGroupOptions: Sendable {
    public enum Action: Sendable {
        case list
        case create(name: String, groupID: String)
        case assign(appID: String, groupID: String)
        case update(name: String, groupID: String)
        case delete(groupID: String)
    }

    public let action: Action
    public let portalOptions: PortalOptions

    public init(action: Action, portalOptions: PortalOptions) {
        self.action = action
        self.portalOptions = portalOptions
    }
}

public struct PortalProfileOptions: Sendable {
    public enum Action: Sendable {
        case list
        case download(bundleID: String, outputPath: String?)
        case delete(profileID: String)
    }

    public let action: Action
    public let portalOptions: PortalOptions

    public init(action: Action, portalOptions: PortalOptions) {
        self.action = action
        self.portalOptions = portalOptions
    }
}

public enum PortalRequestContext: Sendable {
    case list
    case selectTeam(index: String?)
    case selectTeamID(teamID: String)
    case logout(sessionPath: String?, teamID: String?)
    case status(sessionPath: String?, password: String?, encryptPassword: String?, teamID: String?)
    case relogin(PortalOptions)
    case login(PortalLoginOptions)
    case teams(PortalOptions)
    case devices(PortalDeviceOptions)
    case certs(PortalCertOptions)
    case appIDs(PortalAppIDOptions)
    case appGroups(PortalAppGroupOptions)
    case profiles(PortalProfileOptions)
}

