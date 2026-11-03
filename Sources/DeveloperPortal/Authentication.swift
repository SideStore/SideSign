//
//  Authentication.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
import GSACryptoKit

private enum PushedCodeState {
    @TaskLocal static var handled = false
}

/// SideInstaller: after any 2FA succeeds, login again must not re-enter SMS/device flow
/// with a different machine identity (that yields GrandSlam HTTP 503).
private enum Completed2FAState {
    @TaskLocal static var completed = false
}

public extension DeveloperPortal {

    func authenticate(appleID unsanitizedAppleID: String,
                      password: String,
                      anisetteData: AnisetteData,
                      xcodeVersion: String,
                      machinePassword: String? = nil,
                      accountRepairHandler: DeveloperPortal.AccountRepairHandler = DeveloperPortal.defaultAccountRepairHandler,
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
            "svct": customHeaders.grandSlam.service,
            "loc": anisetteData.locale,
            "X-Apple-Locale": anisetteData.locale,
            "X-Apple-I-MD": anisetteData.oneTimePassword,
            "X-Apple-I-MD-M": anisetteData.machineID,
            "X-Mme-Device-Id": anisetteData.deviceID,
            "X-Apple-I-MD-LU": anisetteData.localUserID,
            "X-Apple-I-MD-RINFO": anisetteData.routingInfo,
            "X-Apple-I-SRL-NO": anisetteData.serialNumber,
            "X-Apple-I-Client-Time": anisetteData.clientTime,
            "X-Apple-I-TimeZone": anisetteData.timeZone
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

        let adsid = decryptedDictionary["adsid"] as? String
        let dsidString = (decryptedDictionary["dsid"] as? CustomStringConvertible)?.description
        guard let dsid = adsid ?? dsidString else {
            let jsonStr = prettyJSONString(from: decryptedDictionary)
            debugLog("[SideSign] Decrypted dictionary missing adsid/dsid")
            throw ServerError.missingKey(key: "adsid", jsonPayload: jsonStr)
        }

        let gsIdmsToken = decryptedDictionary["GsIdmsToken"] as? String
        let rawIdmsToken = decryptedDictionary["idmsToken"] as? String
        guard let idmsToken = gsIdmsToken ?? rawIdmsToken else {
            let jsonStr = prettyJSONString(from: decryptedDictionary)
            debugLog("[SideSign] Decrypted dictionary missing GsIdmsToken/idmsToken")
            throw ServerError.missingKey(key: "GsIdmsToken", jsonPayload: jsonStr)
        }

        verboseLog("[SideSign] Parse complete. dsid: \(dsid), token: \(idmsToken)")

        // 2FA auth type
        let statusDictionary = completeResponseDictionary["Status"] as? [String: any Sendable]
        let authType = (statusDictionary?["au"] as? String)
           ?? (completeResponseDictionary["au"] as? String)
           ?? ((statusDictionary?["hsc"] as? Int) == 409 ? "pushedCode" : nil)
        verboseLog("[SideSign] Authentication status type: \(authType ?? "nil")")

        let locked = Self.resolveClientIdentity(from: anisetteData)
        let twoFactorAuthContext = TwoFactorAuthContext(
            dsid: dsid,
            idmsToken: idmsToken,
            anisetteData: anisetteData,
            xcodeVersion: xcodeVersion,
            lockedClientInfo: locked.clientInfo,
            lockedUserAgent: locked.userAgent
        )

        switch authType {
            case "trustedDeviceSecondaryAuth", "trustedDevice", "secondaryAuth", "sms", "voice", "phone", "pushedCode":
                let pushedCode = authType == "pushedCode"
                guard !pushedCode || !PushedCodeState.handled else {
                    throw DeveloperPortalError.requiresTwoFactorAuthentication
                }
                // Already finished 2FA this sign-in — Apple asking again usually means
                // anisette identity changed (new adi). Do not open SMS again.
                if Completed2FAState.completed {
                    debugLog("[SideSign] Apple requested 2FA again after completion (HTTP path) — refusing re-entry")
                    throw ServerError.badServerResponse(
                        reason: "Apple asked for 2FA again after the code was accepted (anisette identity mismatch). Reset adi.pb and sign in once.",
                        jsonPayload: authType ?? ""
                    )
                }
                let isTrustedDevice = pushedCode || authType == "trustedDeviceSecondaryAuth" || authType == "trustedDevice"
                try await handle2FARequest(
                    isTrustedDevice: isTrustedDevice,
                    completeResponseDictionary: completeResponseDictionary,
                    statusDictionary: statusDictionary,
                    context: twoFactorAuthContext,
                    verificationHandler: verificationHandler,
                    codeAlreadySent: pushedCode
                )
                                // SideInstaller: after 2FA, login again with the SAME anisette machine
                // (same adi / MD-M / device). Only clientTime is refreshed.
                // Fetching a new adi mid-session is what produces GrandSlam HTTP 503
                // after the SMS code on every account.
                let formatter = ISO8601DateFormatter()
                formatter.formatOptions = [.withInternetDateTime]
                let lockedCI = twoFactorAuthContext.lockedClientInfo
                let lockedUA = twoFactorAuthContext.lockedUserAgent

                try await Task.sleep(nanoseconds: 5_000_000_000) // SideInstaller: let Apple commit the SMS session

                var lastPost2FAError: Error?
                let postDelays: [UInt64] = [
                    3_000_000_000,
                    8_000_000_000,
                    15_000_000_000,
                    30_000_000_000,
                    45_000_000_000,
                ]
                for attempt in 0..<postDelays.count {
                    if attempt > 0 {
                        try await Task.sleep(nanoseconds: postDelays[attempt])
                    }

                    // SideInstaller get_anisette_data before login again (fresh OTP, same machine)
                    var post2FAAnisette = await Self.refreshOTPKeepingMachine(
                        anisetteData,
                        lockedCI: lockedCI,
                        lockedUA: lockedUA
                    )
                    post2FAAnisette.clientInfo = lockedCI
                    post2FAAnisette.userAgent = lockedUA
                    post2FAAnisette.clientTime = formatter.string(from: Date())

                    debugLog("[SideSign] Post-2FA re-login attempt \(attempt + 1)/\(postDelays.count) same-identity client=\(lockedCI.prefix(48))...")

                    do {
                        return try await Completed2FAState.$completed.withValue(true) {
                            try await PushedCodeState.$handled.withValue(true) {
                                try await authenticate(
                                    appleID: unsanitizedAppleID,
                                    password: password,
                                    anisetteData: post2FAAnisette,
                                    xcodeVersion: xcodeVersion,
                                    machinePassword: machinePassword,
                                    accountRepairHandler: accountRepairHandler,
                                    verificationHandler: verificationHandler
                                )
                            }
                        }
                    } catch {
                        let msg = "\(error)".lowercased()
                        let is503 = msg.contains("503") || msg.contains("433")
                        debugLog("[SideSign] Post-2FA re-login attempt \(attempt + 1) failed: \(error)")
                        if is503, attempt < postDelays.count - 1 {
                            lastPost2FAError = error
                            continue
                        }
                        throw error
                    }
                }
                throw lastPost2FAError ?? ServerError.badServerResponse(
                    reason: "Apple returned HTTP 503 after SMS. Same anisette identity was kept; wait and try once later.",
                    jsonPayload: ""
                )

            case "repair":
                let directRepairURL = completeResponseDictionary["repairUrl"] as? String
                let directURL = completeResponseDictionary["url"] as? String
                let statusURL = (statusDictionary?["url"] as? String)
                let repairURLString = directRepairURL ?? directURL ?? statusURL
                let repairURL = repairURLString.flatMap { URL(string: $0) } ?? Constants.URLs.developerAccount

                let rawMessage = (statusDictionary?["em"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)

                let message: String
                if let rawMessage, !rawMessage.isEmpty {
                    message = rawMessage
                } else {
                    message = Constants.defaultAccountRepairMessage
                }

                debugLog("[SideSign] Account repair required: \(message) (url: \(repairURL.absoluteString)). Prompting accountRepairHandler...")
                let decision = try await accountRepairHandler(repairURL, message)

                if decision == .cancel {
                    debugLog("[SideSign] Account repair cancelled by caller.")
                    throw DeveloperPortalError.accountRepairRequired(url: repairURL, message: message)
                }

                debugLog("[SideSign] Account repair acknowledged by caller. Continuing to fetch app tokens...")

            default:
                break
        }

        guard let sessionKey = decryptedDictionary["sk"] as? Data else {
            debugLog("[SideSign] Decrypted dictionary missing 'sk' key for apptokens")
            throw ServerError.missingKey(key: "sk", jsonPayload: prettyJSONString(from: decryptedDictionary))
        }

        guard let c = decryptedDictionary["c"] as? Data else {
            debugLog("[SideSign] Decrypted dictionary missing 'c' key for apptokens")
            throw ServerError.missingKey(key: "c", jsonPayload: prettyJSONString(from: decryptedDictionary))
        }

        let app = customHeaders.grandSlam.authApp
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

        let fetchedToken = try await fetchAuthToken(app: app, parameters: appTokensParameters, sessionKey: sessionKey, anisetteData: anisetteData)
        let session = Session(
            dsid: dsid,
            authToken: fetchedToken.token,
            anisetteData: anisetteData,
            xcodeVersion: xcodeVersion,
            machinePassword: machinePassword,
            creationDate: fetchedToken.creationDate,
            expirationDate: fetchedToken.expirationDate,
            timeToLive: fetchedToken.timeToLive
        )
        let account = try await fetchAccount(session: session)
        return AuthSession(account: account, session: session)
    }

    func sendAuthenticationRequest(parameters requestParameters: [String: any Sendable], anisetteData: AnisetteData) async throws -> [String: any Sendable] {
        let requestURL = Constants.URLs.grandSlamAuth
        let h = customHeaders

        let parameters: [String: any Sendable] = [
            "Header": ["Version": h.grandSlam.headerVersion],
            "Request": requestParameters
        ]

        let plistData = try PropertyListSerialization.data(fromPropertyList: parameters, format: .xml, options: 0)

        var request = URLRequest(url: requestURL)
        request.httpMethod = "POST"
        request.httpBody = plistData

        // SideInstaller client_info_to_use — one identity; stock/Android/Xcode → safe client.
        // GSA answers stock Xcode-named clients and bad identities with HTTP 503.
        let currentMac = "<MacBookPro18,3> <macOS;26.6;25F84> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
        let currentMacUA = "AuthKit/1 (Macintosh; OS X 26.6) (com.apple.akd/1.0)"

        // SideInstaller 1.6.1: always report CURRENT_MAC through Mac ADI (fixes -80046)
        let clientInfo = currentMac
        let userAgent = currentMacUA

        func applyGrandSlamHeaders(_ req: inout URLRequest, clientInfo: String, userAgent: String) {
            let allHeaders: [String: String] = [
                "Content-Type": "text/x-xml-plist",
                "Accept": "text/x-xml-plist",
                "User-Agent": userAgent,
                "X-Mme-Client-Info": clientInfo,
                "X-Xcode-Version": "14.2 (14C18)",
                "X-Apple-App-Info": h.grandSlam.authApp.isEmpty ? "com.apple.gs.xcode.auth" : h.grandSlam.authApp,
                "X-Apple-I-MD-M": anisetteData.machineID,
                "X-Apple-I-MD": anisetteData.oneTimePassword,
                "X-Apple-I-MD-LU": anisetteData.localUserID,
                "X-Apple-I-MD-RINFO": anisetteData.routingInfo,
                "X-Apple-I-SRL-NO": anisetteData.serialNumber,
                "X-Apple-I-Client-Time": anisetteData.clientTime,
                "X-Apple-Locale": anisetteData.locale,
                "X-Apple-I-TimeZone": anisetteData.timeZone,
                "X-MMe-Device-Id": anisetteData.deviceID,
                "Connection": "close", // SideInstaller: GSA answers reused connections with 5xx
            ]
            allHeaders.forEach { req.setValue($1, forHTTPHeaderField: $0) }
        }

        applyGrandSlamHeaders(&request, clientInfo: clientInfo, userAgent: userAgent)
        if let allHeaders = request.allHTTPHeaderFields {
            verboseLog("[SideSign] sendAuthenticationRequest HTTP headers: \(prettyJSONString(from: sanitizeHeadersForLogging(allHeaders)))")
        }

        // SideInstaller: retry 429; also retry 503 with alternate safe clients (Mac then Windows)
        let retryDelays: [UInt64] = [2_000_000_000, 5_000_000_000, 10_000_000_000, 15_000_000_000]
        // Never switch to Windows mid-session on Mac ADI — that causes -80046 after the code
        let clientFallbacks: [(String, String)] = [
            (currentMac, currentMacUA),
            (currentMac, currentMacUA),
            (currentMac, currentMacUA),
            (currentMac, currentMacUA),
        ]
        var data = Data()
        var response: URLResponse = URLResponse(url: Constants.URLs.grandSlamAuth, mimeType: nil, expectedContentLength: 0, textEncodingName: nil)
        var statusCode = 0
        var attempt = 0
        while true {
            let pair = clientFallbacks[min(attempt, clientFallbacks.count - 1)]
            applyGrandSlamHeaders(&request, clientInfo: pair.0, userAgent: pair.1)
            do {
                (data, response) = try await dataWithFreshConnection(for: request)
            } catch {
                debugLog("[SideSign] sendAuthenticationRequest network error: \(error)")
                throw error
            }
            let httpResponse = response as? HTTPURLResponse
            statusCode = httpResponse?.statusCode ?? 0
            let retryable = statusCode == HTTPStatusCodes.tooManyRequests || statusCode == 503 || statusCode == 433
            if retryable, attempt < retryDelays.count {
                let delay = retryDelays[attempt]
                debugLog("[SideSign] GrandSlam HTTP \(statusCode) — retry \(attempt + 1) in \(delay / 1_000_000_000)s client=\(pair.0.prefix(40))...")
                try await Task.sleep(nanoseconds: delay)
                attempt += 1
                continue
            }
            break
        }

        if statusCode == 503 || statusCode == 433 {
            let rawStr = String(data: data, encoding: .utf8) ?? data.hexEncodedString()
            debugLog("[SideSign] GrandSlam still HTTP \(statusCode) after retries: \(rawStr.prefix(200))")
            throw ServerError.badServerResponse(
                reason: "Apple returned HTTP \(statusCode) on sign-in (often rate-limit or bad anisette). Wait 15–30 minutes, Reset adi.pb, use Auto or a Mac server, try once.",
                jsonPayload: rawStr
            )
        }

        if statusCode != 0 && !(200...299).contains(statusCode) {
            let rawStr = String(data: data, encoding: .utf8) ?? data.hexEncodedString()
            debugLog("[SideSign] GrandSlam HTTP \(statusCode): \(rawStr.prefix(200))")
            // continue to parse if body might be a plist with Status.ec; if empty/HTML, fail below
        }

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

    private struct FetchedAuthToken {
        let token: String
        let creationDate: Date
        let expirationDate: Date?
        let timeToLive: TimeInterval?
    }

    private func fetchAuthToken(app: String, parameters: [String: any Sendable], sessionKey: Data, anisetteData: AnisetteData) async throws -> FetchedAuthToken {
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

        verboseLog("[SideSign] Decrypted GrandSlam response: \(prettyJSONString(from: sanitizeTokens(tokensDictionary)))")

        let now = Date()
        var expirationDate: Date? = nil
        var timeToLive: TimeInterval? = nil

        if let expiry = tokens["expiry"] as? Date {
            expirationDate = expiry
            timeToLive = expiry.timeIntervalSince(now)
        } else if let expiryStr = tokens["expiry"] as? String, let parsed = ISO8601DateFormatter().date(from: expiryStr) {
            expirationDate = parsed
            timeToLive = parsed.timeIntervalSince(now)
        } else if let ttl = tokens["ttl"] as? Double ?? (tokens["ttl"] as? Int).map(Double.init) {
            timeToLive = ttl
            expirationDate = now.addingTimeInterval(ttl)
        } else if let exp = tokens["expiry-date"] as? Date {
            expirationDate = exp
            timeToLive = exp.timeIntervalSince(now)
        } else if let expStr = tokens["expiry-date"] as? String, let parsed = ISO8601DateFormatter().date(from: expStr) {
            expirationDate = parsed
            timeToLive = parsed.timeIntervalSince(now)
        }

        let ttlDesc: String
        if let ttl = timeToLive {
            let days = Int(ttl / 86400)
            let hours = Int((ttl.truncatingRemainder(dividingBy: 86400)) / 3600)
            ttlDesc = "\(days)d \(hours)h (\(Int(ttl))s)"
        } else {
            ttlDesc = "unspecified"
        }

        let expiryDesc = expirationDate.map { ISO8601DateFormatter().string(from: $0) } ?? "unspecified"
        debugLog("[SideSign] Successfully obtained auth token for app: \(app) (TTL: \(ttlDesc), Expiry: \(expiryDesc))")
        return FetchedAuthToken(token: authToken, creationDate: now, expirationDate: expirationDate, timeToLive: timeToLive)
    }

    private func parseTrustedPhoneNumbers(from dict: [String: any Sendable]?) -> [TrustedPhoneNumber] {
        var results: [TrustedPhoneNumber] = []
        let list = (dict?["trustedPhoneNumbers"] as? [[String: any Sendable]])
                ?? (dict?["phoneNumbers"] as? [[String: any Sendable]])
                ?? []
        for item in list {
            if let id = (item["id"] as? CustomStringConvertible)?.description.trimmingCharacters(in: .whitespacesAndNewlines), !id.isEmpty {
                let num = (item["numberWithDialCode"] as? String)
                        ?? (item["obfuscatedNumber"] as? String)
                        ?? (item["lastTwoDigits"] as? String).map { "••\($0)" }
                        ?? "Phone \(id)"
                results.append(TrustedPhoneNumber(id: id, number: num))
            }
        }
        if results.isEmpty, let single = dict?["phoneNumber"] as? [String: any Sendable],
           let id = (single["id"] as? CustomStringConvertible)?.description.trimmingCharacters(in: .whitespacesAndNewlines), !id.isEmpty {
            let num = (single["numberWithDialCode"] as? String)
                    ?? (single["obfuscatedNumber"] as? String)
                    ?? (single["lastTwoDigits"] as? String).map { "••\($0)" }
                    ?? "Phone \(id)"
            results.append(TrustedPhoneNumber(id: id, number: num))
        }
        return results
    }

    private func parseXMLUIAlertMessage(from data: Data) -> (title: String?, message: String?) {
        guard let str = String(data: data, encoding: .utf8) else { return (nil, nil) }
        if str.contains("<pinView") {
            return (nil, nil)
        }
        guard let alertTagRange = str.range(of: #"<alert(?![^>]*\bid=)[^>]*>"#, options: .regularExpression) else {
            return (nil, nil)
        }
        let alertTag = String(str[alertTagRange])
        var title: String?
        var message: String?
        if let titleRange = alertTag.range(of: #"(?<=title=")[^"]+"#, options: .regularExpression) {
            title = String(alertTag[titleRange])
        }
        if let msgRange = alertTag.range(of: #"(?<=message=")[^"]+"#, options: .regularExpression) {
            message = String(alertTag[msgRange])
        }
        return (title, message)
    }

    private func parseXMLUIServerInfo(from data: Data) -> (phoneID: String?, mode: String?) {
        guard let str = String(data: data, encoding: .utf8) else { return (nil, nil) }
        guard let range = str.range(of: #"<serverInfo[^>]*>"#, options: .regularExpression) else { return (nil, nil) }
        let tag = String(str[range])
        var phoneID: String?
        var mode: String?
        if let idRange = tag.range(of: #"(?<=phoneNumber\.id=")[^"]+"#, options: .regularExpression) {
            phoneID = String(tag[idRange])
        }
        if let modeRange = tag.range(of: #"(?<=mode=")[^"]+"#, options: .regularExpression) {
            mode = String(tag[modeRange])
        }
        return (phoneID, mode)
    }

    private func throwIfXMLUIErrorAlert(in data: Data, statusCode: Int, actionName: String) throws {
        let (xmluiTitle, xmluiMessage) = parseXMLUIAlertMessage(from: data)
        if xmluiTitle != nil || xmluiMessage != nil {
            let alertMsg = [xmluiTitle, xmluiMessage]
                .compactMap { $0?.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
                .joined(separator: ": ")
            debugLog("[SideSign] \(actionName) alert from Apple (HTTP \(statusCode)): \(alertMsg)")
            // Always map to PHONE_CODE_REFUSED — never pass Apple's iCloud wording to the UI
            throw DeveloperPortalError.invalid2FAResponse(cause: "PHONE_CODE_REFUSED")
        }
    }

    /// True when Apple's 2FA page refused SMS/voice (often shown as "Could not connect to iCloud").
    private static func isPhoneOrICloudRefuse(_ text: String?) -> Bool {
        guard let t = text?.lowercased(), !t.isEmpty else { return false }
        return t.contains("icloud")
            || t.contains("could not connect")
            || t.contains("phone_code_refused")
            || t == "phone_code_refused"
            || t.contains("could not connect to icloud")
    }

    /// Never show Apple's "Could not connect to iCloud" / internal markers to the user.
    private static func sanitize2FAUserMessage(_ text: String?) -> String {
        guard let text, !text.isEmpty else { return "Apple didn't confirm sending a code to your Apple devices. If one arrived, enter it; if not, try another way." }
        if isPhoneOrICloudRefuse(text) || text == "PHONE_CODE_REFUSED" {
            return "Apple won't send a code by text or call to this sign-in, so it was sent to your Apple devices."
        }
        let lower = text.lowercased()
        if lower.contains("icloud") {
            return "Apple won't send a code by text or call to this sign-in, so it was sent to your Apple devices."
        }
        return text
    }

    private func parseXMLUIObfuscatedNumber(from data: Data) -> String? {
        guard let str = String(data: data, encoding: .utf8) else { return nil }
        let patterns = [
            #"(?:to|at)\s+([+•\d\s\(\)-]{4,25})[.\s<]"#,
            #"([+•\d\s\(\)-]*[•]+[+•\d\s\(\)-]*)"#
        ]
        for pattern in patterns {
            if let matchRange = str.range(of: pattern, options: .regularExpression) {
                let matched = String(str[matchRange])
                    .replacingOccurrences(of: "to ", with: "")
                    .replacingOccurrences(of: "at ", with: "")
                    .trimmingCharacters(in: CharacterSet(charactersIn: ". <\n\r\t"))
                if matched.contains("•") && matched.count >= 3 {
                    return matched
                }
            }
        }
        return nil
    }

    private struct TwoFactorAuthContext {
        let dsid: String
        let idmsToken: String
        let anisetteData: AnisetteData
        let xcodeVersion: String
        /// SideInstaller: same device from start to finish — locked at first GrandSlam request
        let lockedClientInfo: String
        let lockedUserAgent: String
    }

    private struct TwoFactorAuthPhoneCodeResponse {
        let phoneID: String
        let activeMode: String
        let phoneNumbers: [TrustedPhoneNumber]
        let statusCode: Int
    }

    private enum TwoFactorAuthChannel {
        case trustedDevice
        case sms(phoneID: String)
        case voice(phoneID: String)
    }

    private enum TwoFactorAuthValidationResult {
        case success
        case retry(message: String)
    }

    // MARK: - SideInstaller LoginState (apple_account.rs) full 2FA

    /// SideInstaller `LoginState` for the 2FA portion of sign-in.
    private enum SideInstallerLoginState {
        case needsDevice2FA
        case needsDevice2FAVerification
        case needsSMS2FA(phoneID: String)
        case needsSMS2FAVerification(phoneID: String)
    }

    private func handle2FARequest(isTrustedDevice: Bool,
                            completeResponseDictionary: [String: any Sendable],
                            statusDictionary: [String: any Sendable]?,
                            context: TwoFactorAuthContext,
                            verificationHandler: VerificationHandler?,
                            codeAlreadySent: Bool = false) async throws
    {
        guard let verificationHandler else {
            throw DeveloperPortalError.requiresTwoFactorAuthentication
        }

        var phoneNumbers = parseTrustedPhoneNumbers(from: completeResponseDictionary)
        if phoneNumbers.isEmpty, let statusDictionary {
            phoneNumbers = parseTrustedPhoneNumbers(from: statusDictionary)
        }
        let phoneID0 = phoneNumbers.first?.id ?? "1"
        var ctx = context
        var pendingError: String? = nil

        // SideInstaller:
        //   trustedDeviceSecondaryAuth / pushedCode → NeedsDevice2FA
        //   secondaryAuth → NeedsSMS2FA; refuse → NeedsDevice2FA
        var state: SideInstallerLoginState
        if codeAlreadySent || isTrustedDevice {
            state = codeAlreadySent ? .needsDevice2FAVerification : .needsDevice2FA
        } else {
            state = .needsSMS2FA(phoneID: phoneID0)
        }

        let phoneMsg = "Apple won't send a code by text or call to this sign-in, so it was sent to your Apple devices."
        let deviceMsg = "Apple didn't confirm sending a code to your Apple devices. If one arrived, enter it; if not, try another way."

        while true {
            switch state {
            case .needsDevice2FA:
                do { try await sendTrustedDevice2FACodeRequest(context: ctx) } catch {
                    debugLog("[SideSign] SI NeedsDevice2FA soft: \(error)")
                    pendingError = deviceMsg
                }
                state = .needsDevice2FAVerification

            case .needsSMS2FA(let phoneID):
                do {
                    let result = try await sendPhone2FACodeRequest(
                        mode: "sms", phoneID: phoneID, knownPhoneNumbers: phoneNumbers, context: ctx)
                    phoneNumbers = result.phoneNumbers.isEmpty ? phoneNumbers : result.phoneNumbers
                    pendingError = nil
                    state = .needsSMS2FAVerification(phoneID: result.phoneID)
                } catch {
                    debugLog("[SideSign] SI PHONE_CODE_REFUSED → NeedsDevice2FA")
                    pendingError = phoneMsg
                    state = .needsDevice2FA
                }

            case .needsDevice2FAVerification:
                let err = pendingError
                pendingError = nil
                let response = try await verificationHandler(.trustedDevice(error: err))
                switch response {
                case .requestTrustedDevice:
                    state = .needsDevice2FA
                case .requestSMS(let id):
                    state = .needsSMS2FA(phoneID: id)
                case .requestVoice(let id):
                    do {
                        let result = try await sendPhone2FACodeRequest(
                            mode: "voice", phoneID: id, knownPhoneNumbers: phoneNumbers, context: ctx)
                        phoneNumbers = result.phoneNumbers.isEmpty ? phoneNumbers : result.phoneNumbers
                        state = .needsSMS2FAVerification(phoneID: result.phoneID)
                    } catch {
                        pendingError = phoneMsg
                        state = .needsDevice2FA
                    }
                case .verificationCode(let code):
                    let refreshed = await Self.refreshOTPKeepingMachine(
                        ctx.anisetteData, lockedCI: ctx.lockedClientInfo, lockedUA: ctx.lockedUserAgent)
                    ctx = TwoFactorAuthContext(
                        dsid: ctx.dsid, idmsToken: ctx.idmsToken, anisetteData: refreshed,
                        xcodeVersion: ctx.xcodeVersion,
                        lockedClientInfo: ctx.lockedClientInfo, lockedUserAgent: ctx.lockedUserAgent)
                    do {
                        switch try await validateTrustedDevice2FACode(code: code, context: ctx) {
                        case .success:
                            return
                        case .retry(let message):
                            pendingError = Self.sanitize2FAUserMessage(message)
                            state = .needsDevice2FAVerification
                        }
                    } catch {
                        pendingError = Self.sanitize2FAUserMessage("\(error)")
                        state = .needsDevice2FAVerification
                    }
                case .cancel:
                    throw DeveloperPortalError.userCancelled
                }

            case .needsSMS2FAVerification(let phoneID):
                let err = pendingError
                pendingError = nil
                let response = try await verificationHandler(
                    .sms(phoneNumbers: phoneNumbers, activeID: phoneID, error: err))
                switch response {
                case .requestTrustedDevice:
                    state = .needsDevice2FA
                case .requestSMS(let id):
                    state = .needsSMS2FA(phoneID: id)
                case .requestVoice(let id):
                    do {
                        let result = try await sendPhone2FACodeRequest(
                            mode: "voice", phoneID: id, knownPhoneNumbers: phoneNumbers, context: ctx)
                        phoneNumbers = result.phoneNumbers.isEmpty ? phoneNumbers : result.phoneNumbers
                        state = .needsSMS2FAVerification(phoneID: result.phoneID)
                    } catch {
                        pendingError = phoneMsg
                        state = .needsDevice2FA
                    }
                case .verificationCode(let code):
                    let refreshed = await Self.refreshOTPKeepingMachine(
                        ctx.anisetteData, lockedCI: ctx.lockedClientInfo, lockedUA: ctx.lockedUserAgent)
                    ctx = TwoFactorAuthContext(
                        dsid: ctx.dsid, idmsToken: ctx.idmsToken, anisetteData: refreshed,
                        xcodeVersion: ctx.xcodeVersion,
                        lockedClientInfo: ctx.lockedClientInfo, lockedUserAgent: ctx.lockedUserAgent)
                    do {
                        switch try await validatePhone2FACode(
                            code: code, phoneID: phoneID, mode: "sms", context: ctx) {
                        case .success:
                            return
                        case .retry(let message):
                            if Self.isPhoneOrICloudRefuse(message) {
                                pendingError = phoneMsg
                                state = .needsDevice2FA
                            } else {
                                pendingError = Self.sanitize2FAUserMessage(message)
                                state = .needsSMS2FAVerification(phoneID: phoneID)
                            }
                        }
                    } catch {
                        debugLog("[SideSign] SI SMS verify error → NeedsDevice2FA: \(error)")
                        pendingError = phoneMsg
                        state = .needsDevice2FA
                    }
                case .cancel:
                    throw DeveloperPortalError.userCancelled
                }
            }
        }
    }

    private func sendTrustedDevice2FACodeRequest(context: TwoFactorAuthContext) async throws {
        debugLog("[SideSign] Requesting trusted device 2FA code...")
        verboseLog("[SideSign] sendTrustedDevice2FACodeRequest for dsid: \(context.dsid)")

        var request = makeTwoFactorAuthRequest(url: Constants.URLs.trustedDevice, context: context, asMac: false)
        request.httpMethod = "GET"

        if let allHeaders = request.allHTTPHeaderFields {
            verboseLog("[SideSign] sendTrustedDevice2FACodeRequest HTTP headers: \(prettyJSONString(from: sanitizeHeadersForLogging(allHeaders)))")
        }

        do {
            let (data, httpResponse) = try await performTwoFactorRequest(request, context: context, actionName: "sendTrustedDevice2FACodeRequest")
            let statusCode = httpResponse.safeStatusCode
            let rawPreview = String(data: data, encoding: .utf8) ?? ""
            // SideInstaller DEVICE_CODE_UNCONFIRMED: never throw — always allow code entry
            if statusCode != HTTPStatusCodes.ok
                || rawPreview.lowercased().contains("icloud")
                || rawPreview.lowercased().contains("could not connect")
            {
                debugLog("[SideSign] Trusted-device request soft-fail (HTTP \(statusCode)); prompting for code if one arrived")
            } else {
                debugLog("[SideSign] Trusted-device code request accepted")
            }
        } catch {
            debugLog("[SideSign] Trusted-device request error soft-fail: \(error)")
        }
    }

    private func sendPhone2FACodeRequest(mode requestedMode: String,
                                      phoneID requestedPhoneID: String? = nil,
                                      knownPhoneNumbers: [TrustedPhoneNumber] = [],
                                      context: TwoFactorAuthContext) async throws -> TwoFactorAuthPhoneCodeResponse
    {
        debugLog("[SideSign] Requesting secondary/phone 2FA code (mode: \(requestedMode), phoneID: \(requestedPhoneID ?? "auto"))...")
        verboseLog("[SideSign] sendPhone2FACodeRequest for dsid: \(context.dsid), requestedMode: \(requestedMode), phoneID: \(requestedPhoneID ?? "nil")")

        let sanitizedPhoneID: String = {
            if let id = requestedPhoneID?.trimmingCharacters(in: .whitespacesAndNewlines), !id.isEmpty {
                return id
            }
            return "1"
        }()

        // SideInstaller: PUT JSON to https://gsa.apple.com/auth/verify/phone
        let phoneURL = URL(string: "https://gsa.apple.com/auth/verify/phone")!
        var request = makeTwoFactorAuthRequest(url: phoneURL, context: context, asMac: false)
        request.httpMethod = "PUT"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        // SideInstaller uses numeric phone id (u32); default 1
        let phoneIdValue: Int = Int(sanitizedPhoneID) ?? 1
        let jsonBody: [String: Any] = [
            "phoneNumber": ["id": phoneIdValue],
            "mode": requestedMode
        ]
        request.httpBody = try JSONSerialization.data(withJSONObject: jsonBody)

        if let allHeaders = request.allHTTPHeaderFields {
            verboseLog("[SideSign] sendPhone2FACodeRequest HTTP headers: \(prettyJSONString(from: sanitizeHeadersForLogging(allHeaders)))")
        }

        let (data, httpResponse) = try await performTwoFactorRequest(request, context: context, actionName: "sendPhone2FACodeRequest")
        let statusCode = httpResponse.safeStatusCode

        let rawStr = prettyJSONString(from: data)
        verboseLog("[SideSign] sendPhone2FACodeRequest raw response (HTTP \(statusCode)): \(rawStr)")

        // SideInstaller PHONE_CODE_REFUSED: Apple returns "Could not connect to iCloud" / bare 403
        // on Mac-ADI phone 2FA. Surface a consistent error so handle2FA falls back to devices.
        let (xmluiTitle, xmluiMessage) = parseXMLUIAlertMessage(from: data)
        let alertCombined = [xmluiTitle, xmluiMessage]
            .compactMap { $0?.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
            .joined(separator: ": ")
        let alertLower = alertCombined.lowercased()
        if statusCode == 403 || statusCode == 503 || statusCode == 423 || statusCode == 401
            || alertLower.contains("icloud")
            || alertLower.contains("could not connect")
            || alertLower.contains("forbidden")
        {
            let msg = xmluiMessage ?? alertCombined
            if !msg.isEmpty {
                debugLog("[SideSign] sendPhone2FACodeRequest Apple refused phone code (HTTP \(statusCode)): \(msg)")
            } else {
                debugLog("[SideSign] sendPhone2FACodeRequest bare HTTP 403 — phone code refused")
            }
            throw DeveloperPortalError.invalid2FAResponse(cause: "PHONE_CODE_REFUSED")
        }
        if xmluiTitle != nil || xmluiMessage != nil {
            debugLog("[SideSign] sendPhone2FACodeRequest alert from Apple (HTTP \(statusCode)): \(alertCombined)")
            throw DeveloperPortalError.invalid2FAResponse(cause: "PHONE_CODE_REFUSED")
        }

        let responseDict = parsePlistOrJSON(data)
        let errorCode = responseDict?["ec"] as? Int ?? 0
        let errorMsg = (responseDict?["em"] as? String)
                   ?? ((responseDict?["Status"] as? [String: any Sendable])?["em"] as? String)

        // serviceErrors / em may also say Could not connect to iCloud
        let emLower = (errorMsg ?? "").lowercased()
        if emLower.contains("icloud") || emLower.contains("could not connect") {
            debugLog("[SideSign] sendPhone2FACodeRequest service error iCloud refuse: \(errorMsg ?? "")")
            throw DeveloperPortalError.invalid2FAResponse(cause: "PHONE_CODE_REFUSED")
        }

        if errorCode == GrandSlamAuthErrorCodes.tooManyAttempts
            || errorCode == GrandSlamAuthErrorCodes.tooManyCodesRequested
            || errorCode == GrandSlamAuthErrorCodes.rateLimited
            || statusCode == HTTPStatusCodes.tooManyRequests
        {
            let msg = errorMsg ?? "Verification codes cannot be sent to this phone number at this time. Please try again later."
            debugLog("[SideSign] sendPhone2FACodeRequest rate-limited (\(errorCode), HTTP \(statusCode)): \(msg)")
            throw DeveloperPortalError.tooManyAttempts(cause: msg)
        } else if errorCode != 0 {
            let msg = errorMsg ?? "Failed to request verification code from Apple."
            debugLog("[SideSign] sendPhone2FACodeRequest error (\(errorCode), HTTP \(statusCode)): \(msg)")
            throw ServerError.underlyingError(code: errorCode, message: Self.sanitize2FAUserMessage(msg))
        }

        guard statusCode == HTTPStatusCodes.ok else {
            let reason = errorMsg ?? HTTPStatusCodes.localizedDescription(for: statusCode)
            debugLog("[SideSign] sendPhone2FACodeRequest failed (HTTP \(statusCode)): \(reason)")
            // 403 already handled above; any other non-OK still try to soft-signal iCloud-style refusals
            // 423 Locked = phone method locked (same as SideInstaller PHONE_CODE_REFUSED)
            if statusCode == 403 || statusCode == 401 || statusCode == 423 {
                throw DeveloperPortalError.invalid2FAResponse(cause: "PHONE_CODE_REFUSED")
            }
            // Any non-OK phone response → treat as phone refused so UI falls back to devices
            throw DeveloperPortalError.invalid2FAResponse(cause: "PHONE_CODE_REFUSED")
        }

        var parsedNumbers = parseTrustedPhoneNumbers(from: responseDict)
        if parsedNumbers.isEmpty {
            parsedNumbers = knownPhoneNumbers
        }
        let singlePhoneDict = responseDict?["phoneNumber"] as? [String: any Sendable]
        let phoneListFirst = (responseDict?["phoneNumbers"] as? [[String: any Sendable]])?.first
        let trustedPhoneListFirst = (responseDict?["trustedPhoneNumbers"] as? [[String: any Sendable]])?.first
        let phoneDict = singlePhoneDict ?? phoneListFirst ?? trustedPhoneListFirst

        let (xmluiServerPhoneID, xmluiServerMode) = parseXMLUIServerInfo(from: data)

        let rawPhoneID = (phoneDict?["id"] as? CustomStringConvertible)?.description.trimmingCharacters(in: .whitespacesAndNewlines)
        let resolvedPhoneID: String? = (rawPhoneID?.isEmpty == false) ? rawPhoneID : xmluiServerPhoneID
        let resolvedRequestedID: String? = (requestedPhoneID?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false) ? requestedPhoneID : nil

        let phoneID = resolvedPhoneID ?? resolvedRequestedID ?? parsedNumbers.first?.id ?? "1"
        let activeMode = (phoneDict?["mode"] as? String) ?? xmluiServerMode ?? requestedMode

        let numberWithDialCode = phoneDict?["numberWithDialCode"] as? String
        let obfuscatedNumber = phoneDict?["obfuscatedNumber"] as? String
        let lastTwoDigits = (phoneDict?["lastTwoDigits"] as? String).map { "••\($0)" }
        let xmluiNumber = parseXMLUIObfuscatedNumber(from: data)
        let matchedNumber = parsedNumbers.first(where: { $0.id == phoneID })?.number

        let numberObfuscated = numberWithDialCode
                            ?? obfuscatedNumber
                            ?? lastTwoDigits
                            ?? xmluiNumber
                            ?? matchedNumber
                            ?? ""
        if let idx = parsedNumbers.firstIndex(where: { $0.id == phoneID }), !numberObfuscated.isEmpty {
            parsedNumbers[idx] = TrustedPhoneNumber(id: phoneID, number: numberObfuscated)
        } else if parsedNumbers.isEmpty && !numberObfuscated.isEmpty {
            parsedNumbers = [TrustedPhoneNumber(id: phoneID, number: numberObfuscated)]
        }
        debugLog("[SideSign] sendPhone2FACodeRequest received phone response (id: \(phoneID), mode: \(activeMode), number: \(numberObfuscated), total phones: \(parsedNumbers.count))")

        return TwoFactorAuthPhoneCodeResponse(
            phoneID: phoneID,
            activeMode: activeMode,
            phoneNumbers: parsedNumbers,
            statusCode: statusCode
        )
    }

    private func validateTrustedDevice2FACode(code: String, context: TwoFactorAuthContext) async throws -> TwoFactorAuthValidationResult {
        var verifyRequest = makeTwoFactorAuthRequest(url: Constants.URLs.grandSlamValidate, context: context, asMac: false)
        verifyRequest.setValue(code, forHTTPHeaderField: "security-code")

        if let allHeaders = verifyRequest.allHTTPHeaderFields {
            verboseLog("[SideSign] validateTrustedDevice2FACode HTTP headers: \(prettyJSONString(from: sanitizeHeadersForLogging(allHeaders)))")
        }

        debugLog("[SideSign] Verifying trusted device security code...")
        let (verifyData, verifyHttpResponse) = try await performTwoFactorRequest(verifyRequest, context: context, actionName: "validate2FACode")
        let verifyStatusCode = verifyHttpResponse.safeStatusCode

        return try parseTwoFactorAuthVerifyResponse(data: verifyData, statusCode: verifyStatusCode, requirePeToken: false, httpResponse: verifyHttpResponse)
    }

    private func validatePhone2FACode(code: String,
                                      phoneID: String,
                                      mode: String,
                                      context: TwoFactorAuthContext) async throws -> TwoFactorAuthValidationResult
    {
        // SideInstaller: get_anisette_data again before verify (OTP expires ~60s)
        var ctx = context
        let refreshed = await Self.refreshOTPKeepingMachine(
            context.anisetteData,
            lockedCI: context.lockedClientInfo,
            lockedUA: context.lockedUserAgent
        )
        ctx = TwoFactorAuthContext(
            dsid: context.dsid,
            idmsToken: context.idmsToken,
            anisetteData: refreshed,
            xcodeVersion: context.xcodeVersion,
            lockedClientInfo: context.lockedClientInfo,
            lockedUserAgent: context.lockedUserAgent
        )

        // SideInstaller verify_sms_2fa — exact JSON POST
        let securityCodeURL = URL(string: "https://gsa.apple.com/auth/verify/phone/securitycode")!
        var verifyRequest = makeTwoFactorAuthRequest(url: securityCodeURL, context: ctx, asMac: false)
        verifyRequest.httpMethod = "POST"
        verifyRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
        verifyRequest.setValue("application/json", forHTTPHeaderField: "Accept")
        let phoneIdValue: Int = Int(phoneID) ?? 1
        let jsonBody: [String: Any] = [
            "securityCode": ["code": code],
            "phoneNumber": ["id": phoneIdValue],
            "mode": mode
        ]
        verifyRequest.httpBody = try JSONSerialization.data(withJSONObject: jsonBody)

        if let allHeaders = verifyRequest.allHTTPHeaderFields {
            verboseLog("[SideSign] validatePhone2FACode HTTP headers: \(prettyJSONString(from: sanitizeHeadersForLogging(allHeaders)))")
        }

        debugLog("[SideSign] Verifying phone security code (SideInstaller JSON)...")
        let (verifyData, verifyHttpResponse) = try await performTwoFactorRequest(verifyRequest, context: ctx, actionName: "validatePhone2FACode")
        let verifyStatusCode = verifyHttpResponse.safeStatusCode
        // SideInstaller: non-success → parse error; -21669 = wrong code → retry
        if verifyStatusCode == 503 || verifyStatusCode == 433 {
            var lastData = verifyData
            var lastStatus = verifyStatusCode
            var lastHttp = verifyHttpResponse
            for (i, delay) in [UInt64(3_000_000_000), UInt64(8_000_000_000), UInt64(15_000_000_000)].enumerated() {
                debugLog("[SideSign] Phone code submit HTTP \(lastStatus) — retry \(i + 1) after \(delay / 1_000_000_000)s")
                try await Task.sleep(nanoseconds: delay)
                let (retryData, retryHttp) = try await performTwoFactorRequest(verifyRequest, context: ctx, actionName: "validatePhone2FACode-retry")
                lastData = retryData
                lastStatus = retryHttp.safeStatusCode
                lastHttp = retryHttp
                if lastStatus != 503 && lastStatus != 433 { break }
            }
            // Last resort: same JSON body as Mac15,7 (SideInstaller MAC_CLIENT_INFO path)
            if lastStatus == 503 || lastStatus == 433 {
                debugLog("[SideSign] Phone code still HTTP \(lastStatus) — one attempt as MAC_CLIENT_INFO")
                var macReq = makeTwoFactorAuthRequest(url: securityCodeURL, context: ctx, asMac: true)
                macReq.httpMethod = "POST"
                macReq.setValue("application/json", forHTTPHeaderField: "Content-Type")
                macReq.setValue("application/json", forHTTPHeaderField: "Accept")
                macReq.httpBody = verifyRequest.httpBody
                let (macData, macHttp) = try await performTwoFactorRequest(macReq, context: ctx, actionName: "validatePhone2FACode-mac")
                lastData = macData
                lastStatus = macHttp.safeStatusCode
                lastHttp = macHttp
            }
            return try parseTwoFactorAuthVerifyResponse(
                data: lastData,
                statusCode: lastStatus,
                requirePeToken: false,
                httpResponse: lastHttp
            )
        }

        // SideInstaller does not require X-Apple-PE-Token for phone verify success
        return try parseTwoFactorAuthVerifyResponse(
            data: verifyData,
            statusCode: verifyStatusCode,
            requirePeToken: false,
            httpResponse: verifyHttpResponse
        )
    }

    private func parseTwoFactorAuthVerifyResponse(data: Data,
                                                  statusCode: Int,
                                                  requirePeToken: Bool,
                                                  httpResponse: HTTPURLResponse?) throws -> TwoFactorAuthValidationResult
    {
        let verifyDictionary = parsePlistOrJSON(data)
        let (xmluiTitle, xmluiMessage) = parseXMLUIAlertMessage(from: data)
        let errorCode = verifyDictionary?["ec"] as? Int ?? 0
        let statusDict = verifyDictionary?["Status"] as? [String: any Sendable]
        let errorMsg = (verifyDictionary?["em"] as? String)
                    ?? (statusDict?["em"] as? String)
                    ?? xmluiMessage
                    ?? xmluiTitle

        if errorCode == GrandSlamAuthErrorCodes.tooManyAttempts
            || errorCode == GrandSlamAuthErrorCodes.tooManyCodesRequested
            || errorCode == GrandSlamAuthErrorCodes.rateLimited
            || statusCode == HTTPStatusCodes.tooManyRequests
        {
            let msg = errorMsg ?? "Too many verification code attempts. Please try again later."
            debugLog("[SideSign] Too many 2FA attempts (\(errorCode), HTTP \(statusCode)): \(msg)")
            throw DeveloperPortalError.tooManyAttempts(cause: msg)
        } else if errorCode == GrandSlamAuthErrorCodes.incorrectVerificationCode {
            let msg = errorMsg ?? "Incorrect verification code. Please try again."
            debugLog("[SideSign] Incorrect 2FA verification code (\(errorCode), HTTP \(statusCode)): \(msg)")
            return .retry(message: msg)
        } else if errorCode != 0 {
            let msg = errorMsg ?? "2FA verification error"
            debugLog("[SideSign] 2FA verification error (\(errorCode), HTTP \(statusCode)): \(msg)")
            if Self.isPhoneOrICloudRefuse(msg) {
                return .retry(message: "Apple won't send a code by text or call to this sign-in, so it was sent to your Apple devices.")
            }
            throw ServerError.underlyingError(code: errorCode, message: Self.sanitize2FAUserMessage(msg))
        }

        if xmluiTitle != nil || xmluiMessage != nil {
            let message = xmluiMessage ?? errorMsg ?? xmluiTitle ?? "Verification failed"
            debugLog("[SideSign] 2FA verification fatal alert from Apple (HTTP \(statusCode)): \(message)")
            if Self.isPhoneOrICloudRefuse(message) {
                // Treat as wrong channel / refused phone — ask user to use device code
                return .retry(message: "Apple won't send a code by text or call to this sign-in, so it was sent to your Apple devices.")
            }
            throw DeveloperPortalError.invalid2FAResponse(cause: Self.sanitize2FAUserMessage(message))
        }

        if statusCode == 503 || statusCode == 433 {
            debugLog("[SideSign] 2FA verification HTTP \(statusCode) — treating as retryable")
            return .retry(message: "Apple temporarily refused the code (HTTP \(statusCode)). Wait a moment and try again, or use a code from your other Apple devices.")
        }

        guard statusCode == HTTPStatusCodes.ok else {
            let rawStr = prettyJSONString(from: data)
            let reason = errorMsg ?? HTTPStatusCodes.localizedDescription(for: statusCode)
            debugLog("[SideSign] 2FA verification failed (HTTP \(statusCode)): \(reason) - body: \(rawStr)")
            return .retry(message: reason)
        }

        if requirePeToken {
            guard httpResponse?.allHeaderFields.keys.contains(where: { ($0 as? String)?.lowercased() == "x-apple-pe-token" }) == true else {
                let rawStr = prettyJSONString(from: data)
                let reason = errorMsg ?? "Incorrect verification code or missing session token"
                debugLog("[SideSign] Secondary code verification failed (HTTP \(HTTPStatusCodes.ok) missing PE token header): \(reason) - Body: \(rawStr)")
                return .retry(message: reason)
            }
        }

        return .success
    }

    /// SideInstaller MAC_CLIENT_INFO: gsa.apple.com/auth 2FA pages often return a bare 403
    /// for the Windows client used on GrandSlam; retry those requests as a Mac.

    /// SideInstaller client_info_to_use — one identity for the whole sign-in.
    
    /// SideInstaller calls `get_anisette_data` again before "login again" after 2FA.
    /// Fresh OTP (X-Apple-I-MD) avoids GrandSlam HTTP 503 on the post-code SRP.
    private static func refreshAnisetteAfter2FA(
        original: AnisetteData,
        lockedClientInfo: String,
        lockedUserAgent: String
    ) async -> AnisetteData {
        AnisetteDataManager.shared.clearCache()
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]

        // Prefer activeMode; else SideStore's menuAnisetteURL (UserDefaults)
        let mode: AnisetteMode? = AnisetteDataManager.shared.activeMode ?? {
            let urlStr = UserDefaults.standard.string(forKey: "menuAnisetteURL")
                ?? UserDefaults.standard.string(forKey: "defaultServerURL")
                ?? ""
            guard let url = URL(string: urlStr), !urlStr.isEmpty else { return nil }
            return .remote(server: url)
        }()

        guard let mode else {
            debugLog("[SideSign] Post-2FA anisette refresh: no server mode — keeping OTP, fresh clientTime only")
            var copy = original
            copy.clientInfo = lockedClientInfo
            copy.userAgent = lockedUserAgent
            copy.clientTime = formatter.string(from: Date())
            return copy
        }

        let identifier = UUID(uuidString: original.deviceID) ?? UUID()
        var requestHeaders = original.toRequestHeaders()
        requestHeaders.clientInfo = lockedClientInfo
        requestHeaders.userAgent = lockedUserAgent
        requestHeaders.clientTime = formatter.string(from: Date())

        do {
            let (fresh, _) = try await AnisetteDataManager.shared.fetchAnisetteData(
                mode: mode,
                identifier: identifier,
                existingAdiBlob: nil,
                headers: requestHeaders
            )
            var result = fresh
            result.clientInfo = lockedClientInfo
            result.userAgent = lockedUserAgent
            result.clientTime = formatter.string(from: Date())
            if result.deviceID.isEmpty { result.deviceID = original.deviceID }
            if result.machineID.isEmpty { result.machineID = original.machineID }
            debugLog("[SideSign] Post-2FA anisette refresh OK (new OTP)")
            return result
        } catch {
            debugLog("[SideSign] Post-2FA anisette refresh failed (\(error)); using prior headers + new clientTime")
            var copy = original
            copy.clientInfo = lockedClientInfo
            copy.userAgent = lockedUserAgent
            copy.clientTime = formatter.string(from: Date())
            return copy
        }
    }


    
    /// SideInstaller uses a fresh TCP connection per GSA request (pool_max_idle_per_host = 0).
    /// Reused HTTP/2 connections are a known source of GrandSlam HTTP 503.
    private func dataWithFreshConnection(for request: URLRequest) async throws -> (Data, URLResponse) {
        let config = URLSessionConfiguration.ephemeral
        config.httpShouldUsePipelining = false
        config.httpMaximumConnectionsPerHost = 1
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.timeoutIntervalForRequest = 60
        config.timeoutIntervalForResource = 90
        let ephemeral = URLSession(configuration: config)
        defer { ephemeral.invalidateAndCancel() }
        return try await ephemeral.data(for: request)
    }


    /// SideInstaller refreshes anisette before verify_sms and before login again (OTP ~60s).
    /// Same machine (adi / MD-M) when possible; new X-Apple-I-MD only.
    /// SideInstaller refreshes OTP via get_headers on the SAME adi.pb.
    /// Without adi.pb, only bump clientTime — never provision a new machine (that → HTTP 503 after SMS).
    private static func refreshOTPKeepingMachine(_ original: AnisetteData, lockedCI: String, lockedUA: String) async -> AnisetteData {
        AnisetteDataManager.shared.clearCache()
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        let forcedCI = "<MacBookPro18,3> <macOS;26.6;25F84> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
        let forcedUA = "AuthKit/1 (Macintosh; OS X 26.6) (com.apple.akd/1.0)"
        _ = lockedCI
        _ = lockedUA

        func stamp(_ data: AnisetteData) -> AnisetteData {
            var copy = data
            copy.clientInfo = forcedCI
            copy.userAgent = forcedUA
            copy.clientTime = formatter.string(from: Date())
            return copy
        }

        let adiB64 = UserDefaults.standard.string(forKey: "SideSign.anisetteAdiBlob")
            ?? UserDefaults.standard.string(forKey: "anisetteAdiBlob")
        let adiBlob = adiB64.flatMap { Data(base64Encoded: $0) }

        // No saved identity → keep machine + OTP from password step (SideInstaller always has state)
        guard let adiBlob, !adiBlob.isEmpty else {
            debugLog("[SideSign] No adi.pb for OTP refresh — keeping same machine/OTP, new clientTime only")
            return stamp(original)
        }

        let mode: AnisetteMode? = AnisetteDataManager.shared.activeMode ?? {
            let urlStr = UserDefaults.standard.string(forKey: "menuAnisetteURL")
                ?? UserDefaults.standard.string(forKey: "defaultServerURL")
                ?? ""
            guard let url = URL(string: urlStr), !urlStr.isEmpty else { return nil }
            return .remote(server: url)
        }()

        guard let mode else {
            return stamp(original)
        }

        let identifier = UUID(uuidString: original.deviceID) ?? UUID()
        var requestHeaders = original.toRequestHeaders()
        requestHeaders.clientInfo = forcedCI
        requestHeaders.userAgent = forcedUA
        requestHeaders.clientTime = formatter.string(from: Date())

        do {
            let (fresh, newBlob) = try await AnisetteDataManager.shared.fetchAnisetteData(
                mode: mode,
                identifier: identifier,
                existingAdiBlob: adiBlob,
                headers: requestHeaders
            )
            if let newBlob {
                UserDefaults.standard.set(newBlob.base64EncodedString(), forKey: "SideSign.anisetteAdiBlob")
            }
            // Accept full fresh headers for THIS adi only (SideInstaller get_headers)
            var result = stamp(fresh)
            // Hard-lock machine/device from the live session if server returns empty
            if result.machineID.isEmpty { result.machineID = original.machineID }
            if result.deviceID.isEmpty { result.deviceID = original.deviceID }
            if result.oneTimePassword.isEmpty { result.oneTimePassword = original.oneTimePassword }
            debugLog("[SideSign] OTP refreshed with existing adi.pb md-m=\(result.machineID.prefix(12))...")
            return result
        } catch {
            debugLog("[SideSign] OTP refresh failed (\(error)); same machine/OTP + new clientTime")
            return stamp(original)
        }
    }

    private static func resolveClientIdentity(from anisetteData: AnisetteData) -> (clientInfo: String, userAgent: String) {
        // SideInstaller remote_v3::client_info_to_use — exact parity
        let currentMac = "<MacBookPro18,3> <macOS;26.6;25F84> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
        let currentMacUA = "AuthKit/1 (Macintosh; OS X 26.6) (com.apple.akd/1.0)"
        let windows = "<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKit/1 (com.apple.iTunes/12.12.4.1)>"
        let akdUA = "akd/1.0 CFNetwork/808.1.4"
        let advertised = anisetteData.clientInfo.trimmingCharacters(in: .whitespacesAndNewlines)
        let stock = advertised.hasPrefix("<MacBookPro13,2> <macOS;13.1;22C65>")
            || advertised.hasPrefix("<MacBookPro15,1> <Mac OS X;10.15.2;19C57>")
        let android = advertised.contains("<Android;")
        if advertised.isEmpty || android || stock {
            // SideInstaller: Android/stock → Windows; we use CURRENT_MAC when SideStore is on Mac ADI
            // (SideInstaller never logs in through Android ADI anymore)
            return (currentMac, currentMacUA)
        }
        // mac_version < 10.13 (Mac ADI servers name 10.12.6)
        if advertised.contains("10.12") || advertised.contains("Mac OS X;10.11") || advertised.contains("Mac OS X;10.10") {
            return (currentMac, currentMacUA)
        }
        if advertised.contains("MacBook") || advertised.contains("Mac OS") || advertised.contains("macOS") || advertised.contains("<Mac") {
            return (currentMac, currentMacUA)
        }
        if advertised.contains("<PC>") || advertised.contains("Windows") {
            return (windows, akdUA)
        }
        var ua = anisetteData.userAgent.trimmingCharacters(in: .whitespacesAndNewlines)
        if ua.isEmpty { ua = akdUA }
        return (advertised, ua)
    }

    private static let macClientInfoFor2FA = "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"

    private func makeTwoFactorAuthRequest(url: URL, context: TwoFactorAuthContext, asMac: Bool = false) -> URLRequest {
        // SideInstaller build_2fa_headers + send_auth base_headers (minimal set).
        // Extra headers (Client-Time, Locale, SRL-NO, buddyml Accept, etc.) correlate with HTTP 503.
        let identityToken = "\(context.dsid):\(context.idmsToken)"
        let encodedIdentityToken = Data(identityToken.utf8).base64EncodedString()
        let a = context.anisetteData
        let clientInfo = asMac ? Self.macClientInfoFor2FA : context.lockedClientInfo
        let ua = asMac ? "AuthKit/1 (Macintosh; OS X 27.0) (com.apple.akd/1.0)" : context.lockedUserAgent

        var request = URLRequest(url: url)
        // Defaults match SideInstaller non-JSON auth pages; callers override for JSON phone.
        let headers: [String: String] = [
            "Content-Type": "text/x-xml-plist",
            "Accept": "text/x-xml-plist",
            "User-Agent": ua,
            "X-Mme-Client-Info": clientInfo,
            "X-Xcode-Version": "14.2 (14C18)",
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "X-Apple-Identity-Token": encodedIdentityToken,
            // SideInstaller get_headers: only these three anisette fields on 2FA pages
            "X-Mme-Device-Id": a.deviceID,
            "X-Apple-I-MD": a.oneTimePassword,
            "X-Apple-I-MD-M": a.machineID,
            "X-Apple-I-MD-RINFO": a.routingInfo,
            "Connection": "close",
        ]
        headers.forEach { request.setValue($1, forHTTPHeaderField: $0) }
        return request
    }

    private func performTwoFactorRequest(_ request: URLRequest, context: TwoFactorAuthContext, actionName: String) async throws -> (Data, HTTPURLResponse) {
        var current = request
        var triedMac = false
        while true {
            let (data, response) = try await dataWithFreshConnection(for: current)
            let http = response as? HTTPURLResponse
            let status = http?.safeStatusCode ?? 0
            let body = String(data: data, encoding: .utf8) ?? ""

            // SideInstaller refuses_client: only bare 403 (no serviceErrors), not 503
            let hasServiceErrors = body.contains("serviceErrors") || body.contains("\"ec\"") || body.contains("\"ec\" :")
            let bare403 = status == 403 && !hasServiceErrors
            let shouldRetryAsMac = !triedMac && bare403
            if shouldRetryAsMac {
                debugLog("[SideSign] \(actionName) bare HTTP 403 — retrying as MAC_CLIENT_INFO (SideInstaller send_auth)")
                guard let url = current.url else {
                    throw ServerError.badServerResponse(reason: "\(actionName) missing URL", jsonPayload: body)
                }
                var macRequest = makeTwoFactorAuthRequest(url: url, context: context, asMac: true)
                macRequest.httpMethod = current.httpMethod
                macRequest.httpBody = current.httpBody
                // Critical: phone securitycode is JSON — do not reset to text/x-xml-plist (→ HTTP 503)
                if let ct = current.value(forHTTPHeaderField: "Content-Type") {
                    macRequest.setValue(ct, forHTTPHeaderField: "Content-Type")
                }
                if let ac = current.value(forHTTPHeaderField: "Accept") {
                    macRequest.setValue(ac, forHTTPHeaderField: "Accept")
                }
                current = macRequest
                triedMac = true
                continue
            }
            guard let http else {
                throw ServerError.badServerResponse(reason: "\(actionName) non-HTTP response", jsonPayload: body)
            }
            return (data, http)
        }
    }

private func parsePlistOrJSON(_ data: Data) -> [String: any Sendable]? {
           (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: any Sendable]
        ?? (try? JSONSerialization.jsonObject(with: data, options: [])) as? [String: any Sendable]
    }
}
