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
        verboseLog("[SideSign] Authentication status type: \(authType ?? "nil")")

        let twoFactorAuthContext = TwoFactorAuthContext(
            dsid: dsid, 
            idmsToken: idmsToken, 
            anisetteData: anisetteData, 
            xcodeVersion: xcodeVersion
        )

        switch authType {
            case "trustedDeviceSecondaryAuth", "trustedDevice", "secondaryAuth", "sms", "voice", "phone":
                let isTrustedDevice = (authType == "trustedDeviceSecondaryAuth" || authType == "trustedDevice")
                try await handle2FARequest(
                    isTrustedDevice: isTrustedDevice,
                    completeResponseDictionary: completeResponseDictionary,
                    statusDictionary: statusDictionary,
                    context: twoFactorAuthContext,
                    verificationHandler: verificationHandler
                )
                // recur coz we just solved 2FA above and this invocation shouldn't come to this case
                return try await authenticate(
                    appleID: unsanitizedAppleID, 
                    password: password, 
                    anisetteData: anisetteData, 
                    xcodeVersion: xcodeVersion, 
                    machinePassword: machinePassword, 
                    accountRepairHandler: accountRepairHandler, 
                    verificationHandler: verificationHandler
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
            throw DeveloperPortalError.invalid2FAResponse(cause: xmluiMessage ?? alertMsg)
        }
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

    private func handle2FARequest(isTrustedDevice: Bool,
                            completeResponseDictionary: [String: any Sendable],
                            statusDictionary: [String: any Sendable]?,
                            context: TwoFactorAuthContext,
                            verificationHandler: VerificationHandler?) async throws 
    {
        guard let verificationHandler else {
            debugLog("[SideSign] 2FA required but no verificationHandler provided")
            throw DeveloperPortalError.requiresTwoFactorAuthentication
        }

        var phoneNumbers = parseTrustedPhoneNumbers(from: completeResponseDictionary)
        if phoneNumbers.isEmpty, let statusDictionary {
            phoneNumbers = parseTrustedPhoneNumbers(from: statusDictionary)
        }

        let preferredMode: TwoFactorDeliveryMode = isTrustedDevice ? .trustedDevice : .sms

        var currentRequest: TwoFactorRequest = .selectDeliveryMethod(
            preferredMode: preferredMode,
            phoneNumbers: phoneNumbers
        )
        var activeChannel: TwoFactorAuthChannel? = nil

        while true {
            debugLog("[SideSign] Prompting user with 2FA request (\(currentRequest))...")
            let response = try await verificationHandler(currentRequest)

            switch response {
                case .requestTrustedDevice:
                    try await sendTrustedDevice2FACodeRequest(context: context)
                    activeChannel = .trustedDevice
                    currentRequest = .trustedDevice(error: nil)

                case .requestSMS(let targetPhoneID):
                    let result = try await sendPhone2FACodeRequest(mode: "sms", phoneID: targetPhoneID, knownPhoneNumbers: phoneNumbers, context: context)
                    phoneNumbers = result.phoneNumbers
                    activeChannel = .sms(phoneID: result.phoneID)
                    currentRequest = .sms(phoneNumbers: phoneNumbers, activeID: result.phoneID, error: nil)

                case .requestVoice(let targetPhoneID):
                    let result = try await sendPhone2FACodeRequest(mode: "voice", phoneID: targetPhoneID, knownPhoneNumbers: phoneNumbers, context: context)
                    phoneNumbers = result.phoneNumbers
                    activeChannel = .voice(phoneID: result.phoneID)
                    currentRequest = .voice(phoneNumbers: phoneNumbers, activeID: result.phoneID, error: nil)

                case .verificationCode(let code):
                    guard let channel = activeChannel else {
                        debugLog("[SideSign] Unexpected verification code returned before delivery method was selected.")
                        throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Unexpected verification code returned before a delivery method was selected.")
                    }

                    let result: TwoFactorAuthValidationResult
                    switch channel {
                        case .trustedDevice:
                            result = try await validateTrustedDevice2FACode(code: code, context: context)
                        case .sms(let phoneID):
                            result = try await validatePhone2FACode(code: code, phoneID: phoneID, mode: "sms", context: context)
                        case .voice(let phoneID):
                            result = try await validatePhone2FACode(code: code, phoneID: phoneID, mode: "voice", context: context)
                    }

                    switch result {
                        case .success:
                            debugLog("[SideSign] 2FA code verified successfully!")
                            return
                        case .retry(let message):
                            debugLog("[SideSign] 2FA verification failed, retrying: \(message)")
                            switch channel {
                                case .trustedDevice:
                                    currentRequest = .trustedDevice(error: message)
                                case .sms(let phoneID):
                                    currentRequest = .sms(phoneNumbers: phoneNumbers, activeID: phoneID, error: message)
                                case .voice(let phoneID):
                                    currentRequest = .voice(phoneNumbers: phoneNumbers, activeID: phoneID, error: message)
                            }
                    }

                case .cancel:
                    debugLog("[SideSign] User cancelled 2FA.")
                    throw DeveloperPortalError.userCancelled
            }
        }
    }

    private func sendTrustedDevice2FACodeRequest(context: TwoFactorAuthContext) async throws {
        debugLog("[SideSign] Requesting trusted device 2FA code...")
        verboseLog("[SideSign] sendTrustedDevice2FACodeRequest for dsid: \(context.dsid)")

        var request = makeTwoFactorAuthRequest(url: Constants.URLs.trustedDevice, context: context)
        request.httpMethod = "GET"

        let (data, response) = try await session.data(for: request)
        let httpResponse = response as? HTTPURLResponse
        let statusCode = httpResponse?.safeStatusCode ?? 0
        try throwIfXMLUIErrorAlert(in: data, statusCode: statusCode, actionName: "sendTrustedDevice2FACodeRequest")

        guard statusCode == HTTPStatusCodes.ok else {
            let rawStr = prettyJSONString(from: data)
            debugLog("[SideSign] sendTrustedDevice2FACodeRequest failed (HTTP \(statusCode)): \(rawStr)")
            throw ServerError.badServerResponse(reason: "Trusted device request failed (HTTP \(statusCode))", jsonPayload: rawStr)
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

        let serverInfo: [String: any Sendable] = [
            "mode": requestedMode,
            "phoneNumber.id": sanitizedPhoneID
        ]

        var request = makeTwoFactorAuthRequest(url: Constants.URLs.phonePutURL(mode: requestedMode), context: context)
        request.httpMethod = "POST"
        request.httpBody = try PropertyListSerialization.data(fromPropertyList: [
            "serverInfo": serverInfo
        ], format: .xml, options: 0)

        let (data, response) = try await session.data(for: request)
        let httpResponse = response as? HTTPURLResponse
        let statusCode = httpResponse?.safeStatusCode ?? 0

        let rawStr = prettyJSONString(from: data)
        verboseLog("[SideSign] sendPhone2FACodeRequest raw response (HTTP \(statusCode)): \(rawStr)")

        try throwIfXMLUIErrorAlert(in: data, statusCode: statusCode, actionName: "sendPhone2FACodeRequest")

        let responseDict = parsePlistOrJSON(data)
        let errorCode = responseDict?["ec"] as? Int ?? 0
        let errorMsg = (responseDict?["em"] as? String)
                   ?? ((responseDict?["Status"] as? [String: any Sendable])?["em"] as? String)

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
            throw ServerError.underlyingError(code: errorCode, message: msg)
        }

        guard statusCode == HTTPStatusCodes.ok else {
            let reason = errorMsg ?? HTTPStatusCodes.localizedDescription(for: statusCode)
            debugLog("[SideSign] sendPhone2FACodeRequest failed (HTTP \(statusCode)): \(reason)")
            throw ServerError.badServerResponse(reason: reason, jsonPayload: rawStr)
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
        var verifyRequest = makeTwoFactorAuthRequest(url: Constants.URLs.grandSlamValidate, context: context)
        verifyRequest.setValue(code, forHTTPHeaderField: "security-code")

        debugLog("[SideSign] Verifying trusted device security code...")
        let (verifyData, verifyResponse) = try await session.data(for: verifyRequest)
        let verifyHttpResponse = verifyResponse as? HTTPURLResponse
        let verifyStatusCode = verifyHttpResponse?.safeStatusCode ?? 0

        return try parseTwoFactorAuthVerifyResponse(data: verifyData, statusCode: verifyStatusCode, requirePeToken: false, httpResponse: verifyHttpResponse)
    }

    private func validatePhone2FACode(code: String,
                                      phoneID: String,
                                      mode: String,
                                      context: TwoFactorAuthContext) async throws -> TwoFactorAuthValidationResult
    {
        var verifyRequest = makeTwoFactorAuthRequest(url: Constants.URLs.phoneSecurityCode, context: context)
        verifyRequest.httpMethod = "POST"
        verifyRequest.httpBody = try PropertyListSerialization.data(fromPropertyList: [
            "securityCode.code": code,
            "serverInfo": ["mode": mode, "phoneNumber.id": phoneID]
        ], format: .xml, options: 0)

        debugLog("[SideSign] Verifying secondary security code...")
        let (verifyData, verifyResponse) = try await session.data(for: verifyRequest)
        let verifyHttpResponse = verifyResponse as? HTTPURLResponse
        let verifyStatusCode = verifyHttpResponse?.safeStatusCode ?? 0

        return try parseTwoFactorAuthVerifyResponse(data: verifyData, statusCode: verifyStatusCode, requirePeToken: true, httpResponse: verifyHttpResponse)
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
            throw ServerError.underlyingError(code: errorCode, message: msg)
        }

        if xmluiTitle != nil || xmluiMessage != nil {
            let message = xmluiMessage ?? errorMsg ?? xmluiTitle ?? "Verification failed"
            debugLog("[SideSign] 2FA verification fatal alert from Apple (HTTP \(statusCode)): \(message)")
            throw DeveloperPortalError.invalid2FAResponse(cause: message)
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

    private func makeTwoFactorAuthRequest(url: URL, context: TwoFactorAuthContext) -> URLRequest {
        let identityToken = "\(context.dsid):\(context.idmsToken)"
        let encodedIdentityToken = Data(identityToken.utf8).base64EncodedString()

        var request = URLRequest(url: url)
        let headers: [String: String] = [
            "Accept": "application/x-buddyml",
            "Accept-Language": "en-us",
            "Content-Type": "application/x-plist",
            "User-Agent": Constants.xcodeUserAgent,
            "X-Apple-App-Info": Constants.authApp,
            "X-Xcode-Version": context.xcodeVersion,
            "X-Apple-Identity-Token": encodedIdentityToken,
            "X-Apple-I-MD-M": context.anisetteData.machineID,
            "X-Apple-I-MD": context.anisetteData.oneTimePassword,
            "X-Apple-I-MD-LU": context.anisetteData.localUserID,
            "X-Apple-I-MD-RINFO": "\(context.anisetteData.routingInfo)",
            "X-Mme-Device-Id": context.anisetteData.deviceUniqueIdentifier,
            "X-MMe-Client-Info": context.anisetteData.deviceDescription,
            "X-Apple-I-Client-Time": formatDate(context.anisetteData.date),
            "X-Apple-Locale": context.anisetteData.locale.identifier,
            "X-Apple-I-TimeZone": context.anisetteData.timeZone.abbreviation(for: context.anisetteData.date) ?? "PST"
        ]
        headers.forEach { request.setValue($1, forHTTPHeaderField: $0) }
        return request
    }

    private func parsePlistOrJSON(_ data: Data) -> [String: any Sendable]? {
           (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: any Sendable]
        ?? (try? JSONSerialization.jsonObject(with: data, options: [])) as? [String: any Sendable]
    }
}
