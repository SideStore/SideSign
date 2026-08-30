//
//  Errors.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation

public enum DeveloperPortalError: Error, LocalizedError, Sendable {
    case unknown(cause: String? = nil)
    case invalidParameters(cause: String)
    case incorrectCredentials(cause: String? = nil)
    case noTeams
    case appSpecificPasswordRequired(cause: String? = nil)
    case invalidDeviceID(String)
    case deviceAlreadyRegistered(cause: String)
    case invalidCertificateRequest(cause: String)
    case certificateDoesNotExist(serial: String)
    case invalidAppIDName(String)
    case invalidBundleIdentifier(String)
    case bundleIdentifierUnavailable(cause: String)
    case appIDDoesNotExist(identifier: String)
    case maximumAppIDLimitReached(cause: String)
    case invalidAppGroup(String)
    case appGroupDoesNotExist(String)
    case invalidProvisioningProfileIdentifier(String)
    case provisioningProfileDoesNotExist(identifier: String)
    case requiresTwoFactorAuthentication
    case incorrectVerificationCode(cause: String? = nil)
    case authenticationHandshakeFailed(cause: String)
    case invalidAnisetteData(cause: String)
    case tooManyCertificates(cause: String)
    case tooManyAttempts(cause: String)
    case accountRepairRequired(url: URL?, message: String)

    public var errorDescription: String? {
        switch self {
        case .unknown(let cause):                               return cause ?? "An unknown error occurred."
        case .invalidParameters(let cause):                     return "The provided parameters are invalid: \(cause)"
        case .incorrectCredentials(let cause):                  return cause ?? "Your Apple ID or password is incorrect."
        case .noTeams:                                          return "You are not a member of any development teams."
        case .appSpecificPasswordRequired(let cause):           return cause ?? "An app-specific password is required. You can create one at appleid.apple.com."
        case .invalidDeviceID(let id):                          return "This device's UDID is invalid: \(id)"
        case .deviceAlreadyRegistered(let cause):               return "This device is already registered: \(cause)"
        case .invalidCertificateRequest(let cause):             return "The certificate request is invalid: \(cause)"
        case .certificateDoesNotExist(let serial):              return "There is no certificate with serial number '\(serial)' for this team."
        case .invalidAppIDName(let name):                       return "The App ID name contains invalid characters: '\(name)'"
        case .invalidBundleIdentifier(let bundleID):            return "The bundle identifier is invalid: '\(bundleID)'"
        case .bundleIdentifierUnavailable(let cause):           return "Bundle identifier unavailable: \(cause)"
        case .appIDDoesNotExist(let id):                        return "There is no App ID with identifier '\(id)' on this team."
        case .maximumAppIDLimitReached(let cause):              return "Maximum App ID limit reached: \(cause)"
        case .invalidAppGroup(let group):                       return "The provided app group is invalid: '\(group)'"
        case .appGroupDoesNotExist(let group):                  return "App group does not exist: '\(group)'"
        case .invalidProvisioningProfileIdentifier(let id):     return "The identifier for the requested provisioning profile is invalid: '\(id)'"
        case .provisioningProfileDoesNotExist(let id):          return "There is no provisioning profile with identifier '\(id)' on this team."
        case .requiresTwoFactorAuthentication:                  return "This account requires signing in with two-factor authentication."
        case .incorrectVerificationCode(let cause):             return cause ?? "Incorrect verification code."
        case .tooManyAttempts(let cause):                       return cause
        case .authenticationHandshakeFailed(let cause):         return "Authentication handshake failed: \(cause)"
        case .invalidAnisetteData(let cause):                   return "Invalid anisette data: \(cause)"
        case .tooManyCertificates(let cause):                   return "Maximum number of certificates reached: \(cause)"
        case .accountRepairRequired(_, let message):            return message
        }
    }
}

public enum ServerError: LocalizedError, CustomStringConvertible, Sendable {
    case badServerResponse(reason: String, jsonPayload: String)
    case invalidResponseFormat(rawPayload: String)
    case missingKey(key: String, jsonPayload: String)
    case underlyingError(code: Int, message: String)

    public var description: String {
        switch self {
        case .badServerResponse(let reason, let jsonPayload): return "badServerResponse(reason: \"\(reason)\"):\n\(jsonPayload)"
        case .invalidResponseFormat(let rawPayload):          return "invalidResponseFormat:\n\(rawPayload)"
        case .missingKey(let key, let jsonPayload):           return "missingKey(\"\(key)\"):\n\(jsonPayload)"
        case .underlyingError(let code, let message):         return "underlyingError(code: \(code), message: \"\(message)\")"
        }
    }

    public var errorDescription: String? {
        switch self {
        case .badServerResponse(let reason, let jsonPayload): return "Invalid server response: \(reason)\n\(jsonPayload)"
        case .invalidResponseFormat(let rawPayload):          return "Invalid server response: unparseable format\n\(rawPayload)"
        case .missingKey(let key, let jsonPayload):           return "Invalid server response: missing required key '\(key)'\n\(jsonPayload)"
        case .underlyingError(let code, let message):         return "\(message) (\(code))"
        }
    }
}

public enum SignerError: Error, LocalizedError, Sendable {
    case unknown(cause: String? = nil)
    case invalidApp(cause: String)
    case missingAppBundle(path: String)
    case missingInfoPlist(path: String)
    case missingProvisioningProfile(bundleIdentifier: String)

    public var errorDescription: String? {
        switch self {
        case .unknown(let cause):                               return cause ?? "An unknown error occurred during signing."
        case .invalidApp(let cause):                            return "The app is invalid: \(cause)"
        case .missingAppBundle(let path):                       return "The provided path does not contain an app bundle: \(path)"
        case .missingInfoPlist(let path):                       return "The provided app is missing its Info.plist: \(path)"
        case .missingProvisioningProfile(let bundleIdentifier): return "Could not find matching provisioning profile for bundle identifier '\(bundleIdentifier)'."
        }
    }
}

public enum CertificateError: Error, LocalizedError, Sendable {
    case csrGenerationFailed(cause: String)
    case pkcs12ImportFailed(cause: String)
    case pkcs12ExportFailed(cause: String)
    case decryptionFailed(cause: String? = nil)
    case invalidData(cause: String)

    public var errorDescription: String? {
        switch self {
        case .csrGenerationFailed(let cause):  return "CSR generation failed: \(cause)"
        case .pkcs12ImportFailed(let cause):   return "PKCS#12 import failed: \(cause)"
        case .pkcs12ExportFailed(let cause):   return "PKCS#12 export failed: \(cause)"
        case .decryptionFailed(let cause):     return "Decryption failed: \(cause ?? "Incorrect password")"
        case .invalidData(let cause):          return "Invalid certificate data: \(cause)"
        }
    }
}
