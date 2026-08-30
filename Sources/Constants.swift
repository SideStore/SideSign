//
//  Constants.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation

enum Constants {
    static let protocolVersion         = "QH65B2"
    static let servicesProtocolVersion = "v1"
    static let authProtocolVersion     = "A1234"
    static let grandSlamAuthHeader     = "1.0.1"
    static let grandSlamService        = "iCloud"
    static let clientID                = "XABBG36SBA"
    static let appIDKey                = "ba2ec180e6ca6e6c6a542255453b24d6e6e5b2be0cc48bc1b0d8ad64cfe0228f"
    static let userAgent               = "AuthKit/1 (Macintosh; OS X 26.6) (com.apple.dt.Xcode/26.0)"
    static let xcodeUserAgent          = "Xcode"
    static let authApp                 = "com.apple.gs.xcode.auth"
    static let defaultAccountRepairMessage = "Your Apple ID requires account verification or terms agreement.\n" + 
                                             "Please sign in to developer.apple.com or appleid.apple.com."

    enum URLs {
        private static let servicesBase      = "https://developerservices2.apple.com/services/\(Constants.protocolVersion)"

        // Auth
        static let developerAccount          = URL(string: "https://developer.apple.com/account")!
        static let developerServicesBase     = URL(string: "\(servicesBase)/")!
        static let developerServicesV1Base   = URL(string: "https://developerservices2.apple.com/services/\(Constants.servicesProtocolVersion)/")!
        static let appStoreConnectBase       = URL(string: "https://appstoreconnect.apple.com/iris/\(Constants.servicesProtocolVersion)/")!
        static let grandSlamAuth             = URL(string: "https://gsa.apple.com/grandslam/GsService2")!
        static let grandSlamValidate         = URL(string: "https://gsa.apple.com/grandslam/GsService2/validate")!
        static let trustedDevice             = URL(string: "https://gsa.apple.com/auth/verify/trusteddevice")!
        static let trustedDeviceSecurityCode = URL(string: "https://gsa.apple.com/auth/verify/trusteddevice/securitycode")!
        static let phoneBase                 = "https://gsa.apple.com/auth/verify/phone"
        static func phonePutURL(mode: String = "sms") -> URL {
            URL(string: "\(phoneBase)/put?mode=\(mode)") ?? smsPut
        }
        static let phoneSecurityCode         = URL(string: "\(phoneBase)/securitycode?referrer=/auth/verify/phone/put")!
        static let smsPut                    = URL(string: "https://gsa.apple.com/auth/verify/phone/put?mode=sms")!
        static let smsSecurityCode           = URL(string: "https://gsa.apple.com/auth/verify/phone/securitycode?referrer=/auth/verify/phone/put")!

        // Developer Portal Actions
        static let viewDeveloper             = URL(string: "\(servicesBase)/viewDeveloper.action")!
        static let listTeams                 = URL(string: "\(servicesBase)/listTeams.action")!

        // iOS Actions
        static let listAppIDs                = URL(string: "\(servicesBase)/ios/listAppIds.action")!
        static let addAppID                  = URL(string: "\(servicesBase)/ios/addAppId.action")!
        static let updateAppID               = URL(string: "\(servicesBase)/ios/updateAppId.action")!
        static let deleteAppID               = URL(string: "\(servicesBase)/ios/deleteAppId.action")!

        static let listApplicationGroups     = URL(string: "\(servicesBase)/ios/listApplicationGroups.action")!
        static let addApplicationGroup       = URL(string: "\(servicesBase)/ios/addApplicationGroup.action")!
        static let assignApplicationGroup    = URL(string: "\(servicesBase)/ios/assignApplicationGroupToAppId.action")!

        static let listDevices               = URL(string: "\(servicesBase)/ios/listDevices.action")!
        static let addDevice                 = URL(string: "\(servicesBase)/ios/addDevice.action")!

        static let listCertificates          = URL(string: "\(servicesBase)/ios/listAllDevelopmentCerts.action")!
        static let submitCSR                 = URL(string: "\(servicesBase)/ios/submitDevelopmentCSR.action")!

        static let listProvisioningProfiles    = URL(string: "\(servicesBase)/ios/listProvisioningProfiles.action")!
        static let downloadProvisioningProfile = URL(string: "\(servicesBase)/ios/downloadTeamProvisioningProfile.action")!
        static let deleteProvisioningProfile   = URL(string: "\(servicesBase)/ios/deleteProvisioningProfile.action")!
    }

    enum SecondaryAuthType: String, Sendable, CaseIterable {
        case secondaryAuth = "secondaryAuth"
        case sms           = "sms"
        case voice         = "voice"
        case phone         = "phone"
    }
}

enum GrandSlamAuthErrorCodes {
    static let incorrectCredentials                = -22406
    static let appSpecificPasswordRequired         = -20101
    static let appSpecificPasswordRequiredFallback = -20209
    static let incorrectVerificationCode           = -21669
    static let tooManyCodesRequested               = -20102
    static let tooManyAttempts                     = -21668
    static let rateLimited                         = -22411
    static let serverError                         = -22416
}

enum DeveloperPortalResultCodes {
    static let success                             = 0
    static let serviceMappingUnavailable           = 1003
    static let invalidCertificateRequest           = 3250
    static let appGroupDoesNotExist                = 35
    static let deviceAlreadyRegistered             = 35
    static let maximumCertificatesReached          = 35
    static let maximumCertificatesReachedAlternate = 7460
    static let bundleIdentifierUnavailable         = 35
    static let maximumAppIDLimitReached            = 37
    static let appIDDoesNotExist                   = 9115
    static let appIDDoesNotExistAlternate          = 8201
}

enum HTTPStatusCodes {
    static let ok                  = 200
    static let noContent           = 204
    static let badRequest          = 400
    static let unauthorized        = 401
    static let forbidden           = 403
    static let notFound            = 404
    static let tooManyRequests     = 429
    static let internalServerError = 500
    static let badGateway          = 502
    static let serviceUnavailable  = 503
    static let gatewayTimeout      = 504

    static func localizedDescription(for statusCode: Int) -> String {
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

enum UIDeviceFamilyCodes {
    static let iPhone     = 1
    static let iPad       = 2
    static let appleTV    = 3
    static let appleWatch = 4
    static let mac        = 6
    static let visionPro  = 7
}
