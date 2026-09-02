//
//  Constants.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation

public enum Constants {
    public static let protocolVersion         = "QH65B2"
    public static let servicesProtocolVersion = "v1"
    public static let authProtocolVersion     = "A1234"
    public static let grandSlamAuthHeader     = "1.0.1"
    public static let grandSlamService        = "iCloud"
    public static let clientID                = "XABBG36SBA"
    public static let appIDKey                = "ba2ec180e6ca6e6c6a542255453b24d6e6e5b2be0cc48bc1b0d8ad64cfe0228f"
    public static let userAgent               = "AuthKit/1 (Macintosh; OS X 26.6) (com.apple.dt.Xcode/26.0)"
    public static let xcodeUserAgent          = "Xcode"
    public static let authApp                 = "com.apple.gs.xcode.auth"
    public static let defaultAccountRepairMessage = "Your Apple ID requires account verification or terms agreement.\n" + 
                                                    "Please sign in to developer.apple.com or appleid.apple.com."

    public enum URLs {
        private static let servicesBase      = "https://developerservices2.apple.com/services/\(Constants.protocolVersion)"

        // Auth
        public static let developerAccount          = URL(string: "https://developer.apple.com/account")!
        public static let developerServicesBase     = URL(string: "\(servicesBase)/")!
        public static let developerServicesV1Base   = URL(string: "https://developerservices2.apple.com/services/\(Constants.servicesProtocolVersion)/")!
        public static let appStoreConnectBase       = URL(string: "https://appstoreconnect.apple.com/iris/\(Constants.servicesProtocolVersion)/")!
        public static let grandSlamAuth             = URL(string: "https://gsa.apple.com/grandslam/GsService2")!
        public static let grandSlamLookup           = URL(string: "https://gsa.apple.com/grandslam/GsService2/lookup")!
        public static let grandSlamValidate         = URL(string: "https://gsa.apple.com/grandslam/GsService2/validate")!
        public static let trustedDevice             = URL(string: "https://gsa.apple.com/auth/verify/trusteddevice")!
        public static let trustedDeviceSecurityCode = URL(string: "https://gsa.apple.com/auth/verify/trusteddevice/securitycode")!
        public static let phoneBase                 = "https://gsa.apple.com/auth/verify/phone"
        public static func phonePutURL(mode: String = "sms") -> URL {
            URL(string: "\(phoneBase)/put?mode=\(mode)") ?? smsPut
        }
        public static let phoneSecurityCode         = URL(string: "\(phoneBase)/securitycode?referrer=/auth/verify/phone/put")!
        public static let smsPut                    = URL(string: "https://gsa.apple.com/auth/verify/phone/put?mode=sms")!
        public static let smsSecurityCode           = URL(string: "https://gsa.apple.com/auth/verify/phone/securitycode?referrer=/auth/verify/phone/put")!

        // Developer Portal Actions
        public static let viewDeveloper             = URL(string: "\(servicesBase)/viewDeveloper.action")!
        public static let listTeams                 = URL(string: "\(servicesBase)/listTeams.action")!

        // iOS Actions
        public static let listAppIDs                = URL(string: "\(servicesBase)/ios/listAppIds.action")!
        public static let addAppID                  = URL(string: "\(servicesBase)/ios/addAppId.action")!
        public static let updateAppID               = URL(string: "\(servicesBase)/ios/updateAppId.action")!
        public static let deleteAppID               = URL(string: "\(servicesBase)/ios/deleteAppId.action")!

        public static let listApplicationGroups     = URL(string: "\(servicesBase)/ios/listApplicationGroups.action")!
        public static let addApplicationGroup       = URL(string: "\(servicesBase)/ios/addApplicationGroup.action")!
        public static let updateApplicationGroup    = URL(string: "\(servicesBase)/ios/updateApplicationGroup.action")!
        public static let assignApplicationGroup    = URL(string: "\(servicesBase)/ios/assignApplicationGroupToAppId.action")!
        public static let deleteApplicationGroup    = URL(string: "\(servicesBase)/ios/deleteApplicationGroup.action")!

        public static let listDevices               = URL(string: "\(servicesBase)/ios/listDevices.action")!
        public static let addDevice                 = URL(string: "\(servicesBase)/ios/addDevice.action")!
        public static let updateDevice              = URL(string: "\(servicesBase)/ios/updateDevice.action")!
        public static let disableDevice             = URL(string: "\(servicesBase)/ios/disableDevice.action")!
        public static let deleteDevice              = URL(string: "\(servicesBase)/ios/deleteDevice.action")!

        public static let listCertificates          = URL(string: "\(servicesBase)/ios/listAllDevelopmentCerts.action")!
        public static let submitCSR                 = URL(string: "\(servicesBase)/ios/submitDevelopmentCSR.action")!

        public static let listProvisioningProfiles    = URL(string: "\(servicesBase)/ios/listProvisioningProfiles.action")!
        public static let downloadProvisioningProfile = URL(string: "\(servicesBase)/ios/downloadTeamProvisioningProfile.action")!
        public static let deleteProvisioningProfile   = URL(string: "\(servicesBase)/ios/deleteProvisioningProfile.action")!

        // Anisette Endpoints
        public static let v3ClientInfo          = "v3/client_info"
        public static let v3GetHeaders          = "v3/get_headers"
        public static let v3ProvisioningSession = "v3/provisioning_session"
    }

    public enum SecondaryAuthType: String, Sendable, CaseIterable {
        case secondaryAuth = "secondaryAuth"
        case sms           = "sms"
        case voice         = "voice"
        case phone         = "phone"
    }

    public enum Session {
        public static let autoMagic: [UInt8]         = [0x53, 0x53, 0x30, 0x31] // "SS01"
        public static let passMagic: [UInt8]         = [0x53, 0x53, 0x30, 0x32] // "SS02"
        public static let saltLength                 = 16
        public static let nonceLength                = 12
        public static let tagLength                  = 16
        public static let pbkdf2Rounds               = 100_000
        public static let keyOutputLength            = 32
        public static let defaultDirName             = "sidesign"
        public static let defaultConfigDir           = ".config"
        public static let defaultFileName            = "session.dat"
        public static let filePrefix                 = "session_"
        public static let fileExtension              = ".dat"
        public static let machineSeedInfo            = "SideSign.AES-GCM.SessionStorageKey"
        public static let machineSeedDomain          = "SideSign.Session.MachineSeed.v1"
        public static let fallbackSeed               = "SideSignFallbackSeed"
        public static let envXDGConfig               = "XDG_CONFIG_HOME"
        public static let envAppData                 = "APPDATA"
        public static let envHome                    = "HOME"
        public static let envUser                    = "USER"
        public static let envUsername                = "USERNAME"
    }

    public enum DeviceData {
        public static let magic: [UInt8]             = [0x41, 0x44, 0x49, 0x31] // "ADI1"
        public static let defaultFileName            = "machine.dat"
        public static let filePrefix                 = "machine_"
        public static let fileExtension              = ".dat"
    }

    public enum Anisette {
        public static let defaultUserAgent = "akd/1.0 CFNetwork/1408.0.4 Darwin/22.5.0"
        public static let defaultMdLu      = ""
        public static let defaultMdRinfo   = "17106176"
    }
}

public enum GrandSlamAuthErrorCodes {
    public static let incorrectCredentials                = -22406
    public static let appSpecificPasswordRequired         = -20101
    public static let appSpecificPasswordRequiredFallback = -20209
    public static let incorrectVerificationCode           = -21669
    public static let tooManyCodesRequested               = -20102
    public static let tooManyAttempts                     = -21668
    public static let rateLimited                         = -22411
    public static let serverError                         = -22416
}

public enum DeveloperPortalResultCodes {
    public static let success                             = 0
    public static let serviceMappingUnavailable           = 1003
    public static let invalidCertificateRequest           = 3250
    public static let appGroupDoesNotExist                = 35
    public static let deviceAlreadyRegistered             = 35
    public static let maximumCertificatesReached          = 35
    public static let maximumCertificatesReachedAlternate = 7460
    public static let bundleIdentifierUnavailable         = 35
    public static let maximumAppIDLimitReached            = 37
    public static let appIDDoesNotExist                   = 9115
    public static let appIDDoesNotExistAlternate          = 8201
}

public enum HTTPStatusCodes {
    public static let ok                  = 200
    public static let noContent           = 204
    public static let badRequest          = 400
    public static let unauthorized        = 401
    public static let forbidden           = 403
    public static let notFound            = 404
    public static let tooManyRequests     = 429
    public static let internalServerError = 500
    public static let badGateway          = 502
    public static let serviceUnavailable  = 503
    public static let gatewayTimeout      = 504

    public static func localizedDescription(for statusCode: Int) -> String {
        switch statusCode {
        case badRequest:
            return "The server rejected the request parameters."
        case unauthorized:
            return "Your sign-in session expired or is unauthorized."
        case forbidden:
            return "Access to this Apple Developer service was denied."
        case notFound:
            return "The requested Apple service endpoint could not be found."
        case tooManyRequests:
            return "Too many requests sent to Apple. Please wait a few moments and try again."
        case internalServerError:
            return "Apple's authentication servers encountered an internal error."
        case badGateway:
            return "Apple's servers received an invalid gateway response."
        case serviceUnavailable:
            return "Apple Developer Portal is temporarily unavailable or undergoing maintenance."
        case gatewayTimeout:
            return "Apple's servers took too long to respond (connection timed out)."
        default:
            return "Apple service returned an unexpected error (HTTP \(statusCode))."
        }
    }
}

public enum UIDeviceFamilyCodes {
    public static let iPhone     = 1
    public static let iPad       = 2
    public static let appleTV    = 3
    public static let appleWatch = 4
    public static let mac        = 6
    public static let visionPro  = 7
}

