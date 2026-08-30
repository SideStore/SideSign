//
//  Authentication.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
import GSACryptoKit

public extension DeveloperPortal {

    func authenticate(appleID unsanitizedAppleID: String,
                      password: String,
                      anisetteData: AnisetteData,
                      xcodeVersion: String,
                      verificationHandler: DeveloperPortal.VerificationHandler? = nil) async throws -> AuthSession
    {
        let sanitizedAppleID = unsanitizedAppleID.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        debugLog("[SideSign] Starting authenticate...")
        verboseLog("[SideSign] Authenticating Apple ID: \(sanitizedAppleID)")

        let clientDictionary: [String: any Sendable] = [
            "bootstrap": true,
            "icscrec": true,
            "pbe": false,
            "prkgen": true,
            "svct": Constants.grandSlamService,
            "loc": anisetteData.locale.identifier.components(separatedBy: "@").first ?? "en_US",
            "X-Apple-Locale": anisetteData.locale.identifier.components(separatedBy: "@").first ?? "en_US",
            "X-Apple-I-MD": anisetteData.oneTimePassword,
            "X-Apple-I-MD-M": anisetteData.machineID,
            "X-Mme-Device-Id": anisetteData.deviceUniqueIdentifier,
            "X-Apple-I-MD-LU": anisetteData.localUserID,
            "X-Apple-I-MD-RINFO": anisetteData.routingInfo,
            "X-Apple-I-SRL-NO": anisetteData.deviceSerialNumber,
            "X-Apple-I-Client-Time": formatDate(anisetteData.date),
            "X-Apple-I-TimeZone": anisetteData.timeZone.abbreviation(for: anisetteData.date) ?? "PST"
        ]

        guard let srpClient = SRPClient(),
              let publicKey = srpClient.startAuthentication()
        else {
            debugLog("[SideSign] Failed to start SRPClient / generate public key A")
            throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Failed to start SRPClient / generate public key A")
        }

        verboseLog("[SideSign] SRPClient started. Generated public key A: \(publicKey.hexEncodedString())")

        // 1. Send authentication 'init' request
        let initParameters: [String: any Sendable] = [
            "A2k": publicKey,
            "cpd": clientDictionary,
            "ps": ["s2k", "s2k_fo"],
            "o": "init",
            "u": sanitizedAppleID
        ]

        debugLog("[SideSign] Sending authentication 'init' request...")
        let initResponse = try await sendAuthenticationRequest(parameters: initParameters, anisetteData: anisetteData)

        guard let c = initResponse["c"] as? String,
              let salt = initResponse["s"] as? Data,
              let iterations = initResponse["i"] as? Int,
              let serverPublicKey = initResponse["B"] as? Data
        else {
            let payload = prettyJSONString(from: initResponse)
            debugLog("[SideSign] Failed to parse authentication init response dictionary: missing c/s/i/B parameters")
            throw ServerError.badServerResponse(reason: "Auth init response missing c/s/i/B parameters", jsonPayload: payload)
        }

        verboseLog("""
        [SideSign] Received init response:
          • c: \(c)
          • sp: \(initResponse["sp"] as? String ?? "nil")
          • salt: \(salt.hexEncodedString())
          • iterations: \(iterations)
          • B: \(serverPublicKey.hexEncodedString())
        """)

        let sp = initResponse["sp"] as? String
        let isHexadecimal = (sp == "s2k_fo")

        guard let passwordData = password.data(using: .utf8),
              let digest = CryptoUtilities.sha256(passwordData) else {
            debugLog("[SideSign] Failed to compute SHA256 of password")
            throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Failed to compute SHA256 of password")
        }

        let inputDigest: Data = isHexadecimal ? Data(digest.hexEncodedString().utf8) : digest
        guard let derivedPasswordKey = CryptoUtilities.pbkdf2SHA256(
            password: inputDigest,
            salt: salt,
            rounds: iterations,
            outputLength: digest.count
        ) else {
            debugLog("[SideSign] Failed to derive PBKDF2 password key")
            throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Failed to derive PBKDF2 password key")
        }

        guard let verificationMessage = srpClient.processChallenge(
            username: sanitizedAppleID,
            password: derivedPasswordKey,
            salt: salt,
            serverPublicKey: serverPublicKey
        ) else {
            debugLog("[SideSign] SRP challenge processing failed")
            throw DeveloperPortalError.authenticationHandshakeFailed(cause: "SRP challenge processing failed")
        }

        debugLog("[SideSign] Initiating SRP authentication step 2 (complete)...")
        verboseLog("[SideSign] Generated verification message M1: \(verificationMessage.hexEncodedString())")

        // 2. Send authentication 'complete' request
        let completeParameters: [String: any Sendable] = [
            "c": c,
            "cpd": clientDictionary,
            "M1": verificationMessage,
            "o": "complete",
            "u": sanitizedAppleID
        ]

        let completeResponseDictionary = try await sendAuthenticationRequest(parameters: completeParameters, anisetteData: anisetteData)
        debugLog("[SideSign] SRP complete step finished.")

        guard let encryptedData = completeResponseDictionary["spd"] as? Data else {
            let payload = prettyJSONString(from: completeResponseDictionary)
            debugLog("[SideSign] Missing encrypted data 'spd' in auth complete response: \(payload)")
            throw ServerError.missingKey(key: "spd", jsonPayload: payload)
        }

        guard let serverVerificationMessage = completeResponseDictionary["M2"] as? Data else {
            let payload = prettyJSONString(from: completeResponseDictionary)
            debugLog("[SideSign] Missing server verification message 'M2' in auth complete response: \(payload)")
            throw ServerError.missingKey(key: "M2", jsonPayload: payload)
        }

        verboseLog("""
        [SideSign] Received SPD payload:
          • Encrypted SPD bytes: \(encryptedData.count)
          • M2: \(serverVerificationMessage.hexEncodedString())
        """)

        guard srpClient.verifyServerProof(serverVerificationMessage) else {
            debugLog("[SideSign] Server M2 verification message validation failed")
            throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Server verification proof (M2) mismatch")
        }

        guard let sharedSecret = srpClient.sessionKey() else {
            debugLog("[SideSign] Failed to obtain session key from SRPClient")
            throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Missing session key")
        }

        guard let spdKey = CryptoUtilities.hmacSHA256(key: sharedSecret, strings: ["extra data key:"]),
              let spdIV = CryptoUtilities.hmacSHA256(key: sharedSecret, strings: ["extra data iv:"]),
              let decryptedData = CryptoUtilities.aesCBCDecrypt(key: spdKey, iv: spdIV, ciphertext: encryptedData)
        else {
            debugLog("[SideSign] Decryption of SPD payload failed")
            throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Failed to AES-CBC decrypt SPD payload")
        }

        guard let decryptedDictionary = parsePlistOrJSON(decryptedData) else {
            let rawDecrypted = prettyJSONString(from: decryptedData)
            debugLog("[SideSign] Decrypted payload format is invalid (neither Plist nor JSON)")
            throw ServerError.invalidResponseFormat(rawPayload: rawDecrypted)
        }

        guard let dsid = (decryptedDictionary["adsid"] as? String) ?? (decryptedDictionary["dsid"] as? CustomStringConvertible)?.description else {
            let jsonStr = prettyJSONString(from: decryptedDictionary)
            debugLog("[SideSign] Decrypted dictionary missing adsid/dsid")
            throw ServerError.missingKey(key: "adsid", jsonPayload: jsonStr)
        }

        guard let idmsToken = (decryptedDictionary["GsIdmsToken"] as? String) ?? (decryptedDictionary["idmsToken"] as? String) else {
            let jsonStr = prettyJSONString(from: decryptedDictionary)
            debugLog("[SideSign] Decrypted dictionary missing GsIdmsToken/idmsToken")
            throw ServerError.missingKey(key: "GsIdmsToken", jsonPayload: jsonStr)
        }

        verboseLog("[SideSign] Parse complete. dsid: \(dsid), token: \(idmsToken)")

        let authType = ((completeResponseDictionary["Status"] as? [String: any Sendable])?["au"] as? String)
            ?? (completeResponseDictionary["au"] as? String)
        verboseLog("[SideSign] Authentication status type: \(authType ?? "nil")")

        switch authType {
        case "trustedDeviceSecondaryAuth", "trustedDevice":
            guard let verificationHandler else {
                debugLog("[SideSign] Trusted device 2FA required but no verificationHandler provided")
                throw DeveloperPortalError.requiresTwoFactorAuthentication
            }
            try await requestTrustedDeviceTwoFactorCode(dsid: dsid, idmsToken: idmsToken, anisetteData: anisetteData, xcodeVersion: xcodeVersion, verificationHandler: verificationHandler)
            return try await authenticate(appleID: unsanitizedAppleID, password: password, anisetteData: anisetteData, xcodeVersion: xcodeVersion, verificationHandler: verificationHandler)

        case _ where authType.flatMap(Constants.SecondaryAuthType.init) != nil:
            guard let verificationHandler else {
                debugLog("[SideSign] Secondary 2FA required but no verificationHandler provided")
                throw DeveloperPortalError.requiresTwoFactorAuthentication
            }
            let secondaryType = authType.flatMap(Constants.SecondaryAuthType.init)
            let requestedMode = (secondaryType == .voice) ? Constants.SecondaryAuthType.voice.rawValue : Constants.SecondaryAuthType.sms.rawValue
            try await requestSMSTwoFactorCode(mode: requestedMode, dsid: dsid, idmsToken: idmsToken, anisetteData: anisetteData, xcodeVersion: xcodeVersion, verificationHandler: verificationHandler)
            return try await authenticate(appleID: unsanitizedAppleID, password: password, anisetteData: anisetteData, xcodeVersion: xcodeVersion, verificationHandler: verificationHandler)

        case "repair":
            let repairURLString = (completeResponseDictionary["repairUrl"] as? String)
                ?? (completeResponseDictionary["url"] as? String)
                ?? ((completeResponseDictionary["Status"] as? [String: any Sendable])?["url"] as? String)
            let repairURL = repairURLString.flatMap { URL(string: $0) } ?? Constants.URLs.developerAccount
            let message = ((completeResponseDictionary["Status"] as? [String: any Sendable])?["em"] as? String)
                ?? Constants.defaultAccountRepairMessage
            debugLog("[SideSign] Account repair required: \(message) (url: \(repairURL.absoluteString))")
            throw DeveloperPortalError.accountRepairRequired(url: repairURL, message: message)

        default:
            guard let sessionKey = decryptedDictionary["sk"] as? Data else {
                debugLog("[SideSign] Decrypted dictionary missing 'sk' key for apptokens")
                throw ServerError.missingKey(key: "sk", jsonPayload: prettyJSONString(from: decryptedDictionary))
            }

            guard let c = decryptedDictionary["c"] as? Data else {
                debugLog("[SideSign] Decrypted dictionary missing 'c' key for apptokens")
                throw ServerError.missingKey(key: "c", jsonPayload: prettyJSONString(from: decryptedDictionary))
            }

            let app = Constants.authApp
            guard let checksum = CryptoUtilities.hmacSHA256(key: sessionKey, strings: ["apptokens", dsid, app]) else {
                debugLog("[SideSign] Failed to compute apptokens checksum")
                throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Failed to compute apptokens checksum")
            }

            let appTokensParameters: [String: any Sendable] = [
                "app": [app],
                "c": c,
                "checksum": checksum,
                "cpd": clientDictionary,
                "o": "apptokens",
                "t": idmsToken,
                "u": dsid
            ]

            let authToken = try await fetchAuthToken(app: app, parameters: appTokensParameters, sessionKey: sessionKey, anisetteData: anisetteData)
            let session = Session(dsid: dsid, authToken: authToken, anisetteData: anisetteData, xcodeVersion: xcodeVersion)
            let account = try await fetchAccount(session: session)
            return AuthSession(account: account, session: session)
        }
    }

    private func sendAuthenticationRequest(parameters requestParameters: [String: any Sendable], anisetteData: AnisetteData) async throws -> [String: any Sendable] {
        let requestURL = Constants.URLs.grandSlamAuth

        let parameters: [String: any Sendable] = [
            "Header": ["Version": Constants.grandSlamAuthHeader],
            "Request": requestParameters
        ]

        let plistData = try PropertyListSerialization.data(fromPropertyList: parameters, format: .xml, options: 0)

        var request = URLRequest(url: requestURL)
        request.httpMethod = "POST"
        request.httpBody = plistData

        let headers: [String: String] = [
            "Content-Type": "text/x-xml-plist",
            "X-MMe-Client-Info": anisetteData.deviceDescription,
            "Accept": "*/*",
            "User-Agent": Constants.userAgent
        ]
        headers.forEach { request.setValue($1, forHTTPHeaderField: $0) }

        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            debugLog("[SideSign] sendAuthenticationRequest network error: \(error)")
            throw error
        }

        let httpResponse = response as? HTTPURLResponse
        let statusCode = httpResponse?.statusCode ?? 0

        guard !data.isEmpty else {
            debugLog("[SideSign] Auth endpoint returned 0 bytes (HTTP \(statusCode))")
            throw ServerError.badServerResponse(reason: "Auth endpoint returned empty response (0 bytes)", jsonPayload: "0 bytes")
        }

        guard let responseDictionary = parsePlistOrJSON(data) else {
            let rawStr = String(data: data, encoding: .utf8) ?? data.hexEncodedString()
            debugLog("[SideSign] Auth endpoint returned invalid response format: \(rawStr)")
            throw ServerError.invalidResponseFormat(rawPayload: rawStr)
        }

        let dictionary = (responseDictionary["Response"] as? [String: any Sendable]) ?? responseDictionary
        guard let status = dictionary["Status"] as? [String: any Sendable] else {
            let rawStr = prettyJSONString(from: responseDictionary)
            debugLog("[SideSign] Auth endpoint response missing 'Status': \(rawStr)")
            throw ServerError.missingKey(key: "Status", jsonPayload: rawStr)
        }

        let errorCode = status["ec"] as? Int ?? 0
        if errorCode != 0 {
            let errorDesc = status["em"] as? String
            debugLog("[SideSign] Auth endpoint returned error code \(errorCode): \(errorDesc ?? "No error message")")
            switch errorCode {
            case GrandSlamAuthErrorCodes.incorrectCredentials:
                throw DeveloperPortalError.incorrectCredentials(cause: errorDesc)
            case GrandSlamAuthErrorCodes.appSpecificPasswordRequired,
                 GrandSlamAuthErrorCodes.appSpecificPasswordRequiredFallback:
                throw DeveloperPortalError.appSpecificPasswordRequired(cause: errorDesc)
            case GrandSlamAuthErrorCodes.incorrectVerificationCode:
                throw DeveloperPortalError.incorrectVerificationCode(cause: errorDesc)
            default:
                throw ServerError.underlyingError(code: errorCode, message: errorDesc ?? "Authentication failed")
            }
        }

        return dictionary
    }

    private func fetchAuthToken(app: String, parameters: [String: any Sendable], sessionKey: Data, anisetteData: AnisetteData) async throws -> String {
        let responseDictionary = try await sendAuthenticationRequest(parameters: parameters, anisetteData: anisetteData)

        guard let encryptedToken = responseDictionary["et"] as? Data else {
            let payload = prettyJSONString(from: responseDictionary)
            debugLog("[SideSign] fetchAuthToken missing 'et' key in response")
            throw ServerError.missingKey(key: "et", jsonPayload: payload)
        }

        guard encryptedToken.count > 35 else {
            debugLog("[SideSign] Encrypted token payload is too short (length: \(encryptedToken.count))")
            throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Encrypted token payload is too short (\(encryptedToken.count) bytes)")
        }

        let aad = Data(encryptedToken[..<3])
        let nonce = Data(encryptedToken[3..<19])
        let ciphertext = Data(encryptedToken[19..<(encryptedToken.count - 16)])
        let tag = Data(encryptedToken[(encryptedToken.count - 16)...])

        guard let token = CryptoUtilities.aesGCMDecrypt(key: sessionKey, nonce: nonce, aad: aad, ciphertext: ciphertext, tag: tag) else {
            debugLog("[SideSign] Failed to AES-GCM decrypt auth token")
            throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Failed to AES-GCM decrypt auth token")
        }

        guard let tokensDictionary = parsePlistOrJSON(token) else {
            let rawStr = prettyJSONString(from: token)
            debugLog("[SideSign] Failed to parse decrypted token dictionary")
            throw ServerError.invalidResponseFormat(rawPayload: rawStr)
        }

        guard let appTokens = tokensDictionary["t"] as? [String: any Sendable],
              let tokens = appTokens[app] as? [String: any Sendable],
              let authToken = tokens["token"] as? String
        else {
            let payload = prettyJSONString(from: tokensDictionary)
            debugLog("[SideSign] Decrypted tokens missing t/\(app)/token")
            throw ServerError.missingKey(key: "t/\(app)/token", jsonPayload: payload)
        }

        debugLog("[SideSign] Successfully obtained auth token for app: \(app)")
        return authToken
    }

    private func requestTrustedDeviceTwoFactorCode(dsid: String,
                                                   idmsToken: String,
                                                   anisetteData: AnisetteData,
                                                   xcodeVersion: String,
                                                   verificationHandler: VerificationHandler) async throws
    {
        debugLog("[SideSign] Requesting trusted device 2FA code...")
        verboseLog("[SideSign] requestTrustedDeviceTwoFactorCode for dsid: \(dsid)")

        var request = makeTwoFactorRequest(url: Constants.URLs.trustedDevice, dsid: dsid, idmsToken: idmsToken, anisetteData: anisetteData, xcodeVersion: xcodeVersion)
        request.httpMethod = "GET"

        let (data, response) = try await session.data(for: request)
        let httpResponse = response as? HTTPURLResponse
        let statusCode = httpResponse?.statusCode ?? 0

        guard statusCode == HTTPStatusCodes.ok else {
            let rawStr = prettyJSONString(from: data)
            debugLog("[SideSign] requestTrustedDeviceTwoFactorCode failed (HTTP \(statusCode)): \(rawStr)")
            throw ServerError.badServerResponse(reason: "Trusted device request failed (HTTP \(statusCode))", jsonPayload: rawStr)
        }

        debugLog("[SideSign] Prompting user for 2FA code via verificationHandler...")
        let code: String = try await withCheckedThrowingContinuation { continuation in
            verificationHandler(.trustedDevice) { enteredCode in
                if let enteredCode {
                    debugLog("[SideSign] User entered 2FA code.")
                    continuation.resume(returning: enteredCode)
                } else {
                    debugLog("[SideSign] User cancelled 2FA code entry.")
                    continuation.resume(throwing: DeveloperPortalError.requiresTwoFactorAuthentication)
                }
            }
        }

        var verifyRequest = makeTwoFactorRequest(url: Constants.URLs.grandSlamValidate, dsid: dsid, idmsToken: idmsToken, anisetteData: anisetteData, xcodeVersion: xcodeVersion)
        verifyRequest.setValue(code, forHTTPHeaderField: "security-code")

        debugLog("[SideSign] Verifying trusted device security code...")
        let (verifyData, verifyResponse) = try await session.data(for: verifyRequest)
        let verifyHttpResponse = verifyResponse as? HTTPURLResponse
        let verifyStatusCode = verifyHttpResponse?.statusCode ?? 0

        guard let verifyDictionary = parsePlistOrJSON(verifyData) else {
            let rawStr = prettyJSONString(from: verifyData)
            debugLog("[SideSign] Verify response invalid format: \(rawStr) (status \(verifyStatusCode))")
            throw ServerError.invalidResponseFormat(rawPayload: rawStr)
        }

        let errorCode = verifyDictionary["ec"] as? Int ?? 0
        let errorMsg = (verifyDictionary["em"] as? String) ?? "2FA verification failed"
        if errorCode == GrandSlamAuthErrorCodes.incorrectVerificationCode {
            debugLog("[SideSign] Incorrect 2FA verification code entered (\(errorCode)): \(errorMsg)")
            throw DeveloperPortalError.incorrectVerificationCode(cause: errorMsg)
        } else if errorCode != 0 {
            debugLog("[SideSign] 2FA verification error (\(errorCode)): \(errorMsg)")
            throw ServerError.underlyingError(code: errorCode, message: errorMsg)
        }

        debugLog("[SideSign] Trusted device 2FA code verified successfully!")
    }

    private func requestSMSTwoFactorCode(mode requestedMode: String = "sms",
                                         dsid: String,
                                         idmsToken: String,
                                         anisetteData: AnisetteData,
                                         xcodeVersion: String,
                                         verificationHandler: VerificationHandler) async throws
    {
        debugLog("[SideSign] Requesting secondary/phone 2FA code (mode: \(requestedMode))...")
        verboseLog("[SideSign] requestSMSTwoFactorCode for dsid: \(dsid), requestedMode: \(requestedMode)")

        var request = makeTwoFactorRequest(url: Constants.URLs.phonePutURL(mode: requestedMode), dsid: dsid, idmsToken: idmsToken, anisetteData: anisetteData, xcodeVersion: xcodeVersion)
        request.httpMethod = "POST"
        request.httpBody = try PropertyListSerialization.data(fromPropertyList: [
            "serverInfo": [
                "mode": requestedMode,
                "phoneNumber.id": "1"
            ]
        ], format: .xml, options: 0)

        let (data, response) = try await session.data(for: request)
        let httpResponse = response as? HTTPURLResponse
        let statusCode = httpResponse?.statusCode ?? 0

        let responseDict = parsePlistOrJSON(data)
        let phoneDict = (responseDict?["phoneNumber"] as? [String: any Sendable])
            ?? ((responseDict?["phoneNumbers"] as? [[String: any Sendable]])?.first)
        let phoneID = (phoneDict?["id"] as? CustomStringConvertible)?.description ?? "1"
        let activeMode = (phoneDict?["mode"] as? String) ?? requestedMode
        let twoFactorMode: TwoFactorMode = (activeMode == "voice") ? .voice : .sms

        debugLog("[SideSign] Prompting user for 2FA code via verificationHandler (request status: \(statusCode), phoneId: \(phoneID), mode: \(activeMode))...")
        let code: String = try await withCheckedThrowingContinuation { continuation in
            verificationHandler(twoFactorMode) { enteredCode in
                if let enteredCode, !enteredCode.isEmpty {
                    debugLog("[SideSign] User entered 2FA code.")
                    continuation.resume(returning: enteredCode)
                } else {
                    debugLog("[SideSign] User cancelled 2FA code entry.")
                    continuation.resume(throwing: DeveloperPortalError.requiresTwoFactorAuthentication)
                }
            }
        }

        var verifyRequest = makeTwoFactorRequest(url: Constants.URLs.phoneSecurityCode, dsid: dsid, idmsToken: idmsToken, anisetteData: anisetteData, xcodeVersion: xcodeVersion)
        verifyRequest.httpMethod = "POST"
        verifyRequest.httpBody = try PropertyListSerialization.data(fromPropertyList: [
            "securityCode.code": code,
            "serverInfo": ["mode": activeMode, "phoneNumber.id": phoneID]
        ], format: .xml, options: 0)

        debugLog("[SideSign] Verifying secondary security code...")
        let (verifyData, verifyResponse) = try await session.data(for: verifyRequest)

        if let verifyDict = parsePlistOrJSON(verifyData) {
            let errorCode = verifyDict["ec"] as? Int ?? 0
            if errorCode == GrandSlamAuthErrorCodes.incorrectVerificationCode {
                let errorMsg = (verifyDict["em"] as? String) ?? "Incorrect verification code"
                debugLog("[SideSign] Incorrect 2FA verification code (\(errorCode)): \(errorMsg)")
                throw DeveloperPortalError.incorrectVerificationCode(cause: errorMsg)
            } else if errorCode != 0 {
                let errorMsg = (verifyDict["em"] as? String) ?? "2FA verification error"
                debugLog("[SideSign] 2FA verification error (\(errorCode)): \(errorMsg)")
                throw ServerError.underlyingError(code: errorCode, message: errorMsg)
            }
        }

        guard let verifyHttpResponse = verifyResponse as? HTTPURLResponse,
              verifyHttpResponse.statusCode == HTTPStatusCodes.ok,
              verifyHttpResponse.allHeaderFields.keys.contains(where: { ($0 as? String)?.lowercased() == "x-apple-pe-token" })
        else {
            debugLog("[SideSign] Secondary code verification failed (missing PE token or status != \(HTTPStatusCodes.ok))")
            throw DeveloperPortalError.incorrectVerificationCode(cause: "Missing PE token or status != \(HTTPStatusCodes.ok)")
        }

        debugLog("[SideSign] Secondary 2FA code verified successfully!")
    }

    private func makeTwoFactorRequest(url: URL,
                                      dsid: String,
                                      idmsToken: String,
                                      anisetteData: AnisetteData,
                                      xcodeVersion: String) -> URLRequest
    {
        let identityToken = "\(dsid):\(idmsToken)"
        let encodedIdentityToken = Data(identityToken.utf8).base64EncodedString()

        var request = URLRequest(url: url)
        let headers: [String: String] = [
            "Accept": "application/x-buddyml",
            "Accept-Language": "en-us",
            "Content-Type": "application/x-plist",
            "User-Agent": Constants.xcodeUserAgent,
            "X-Apple-App-Info": Constants.authApp,
            "X-Xcode-Version": xcodeVersion,
            "X-Apple-Identity-Token": encodedIdentityToken,
            "X-Apple-I-MD-M": anisetteData.machineID,
            "X-Apple-I-MD": anisetteData.oneTimePassword,
            "X-Apple-I-MD-LU": anisetteData.localUserID,
            "X-Apple-I-MD-RINFO": "\(anisetteData.routingInfo)",
            "X-Mme-Device-Id": anisetteData.deviceUniqueIdentifier,
            "X-MMe-Client-Info": anisetteData.deviceDescription,
            "X-Apple-I-Client-Time": formatDate(anisetteData.date),
            "X-Apple-Locale": anisetteData.locale.identifier,
            "X-Apple-I-TimeZone": anisetteData.timeZone.abbreviation(for: anisetteData.date) ?? "PST"
        ]
        headers.forEach { request.setValue($1, forHTTPHeaderField: $0) }
        return request
    }

    private func parsePlistOrJSON(_ data: Data) -> [String: any Sendable]? {
           (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: any Sendable]
        ?? (try? JSONSerialization.jsonObject(with: data, options: [])) as? [String: any Sendable]
    }
}
