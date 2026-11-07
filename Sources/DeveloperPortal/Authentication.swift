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

        // SideInstaller AnisetteData::get_client_provided_data — only these anisette fields in CPD.
        // Extra LU/RINFO/SRL/Client-Time in CPD has been correlated with -80045 on mismatched builds.
        let clientDictionary: [String: any Sendable] = [
            "bootstrap": true,
            "icscrec": true,
            "pbe": false,
            "prkgen": true,
            "svct": customHeaders.grandSlam.service.isEmpty ? "iCloud" : customHeaders.grandSlam.service,
            "loc": anisetteData.locale.isEmpty ? "en_US" : anisetteData.locale,
            "X-Mme-Device-Id": anisetteData.deviceID,
            "X-Apple-I-MD": anisetteData.oneTimePassword,
            "X-Apple-I-MD-M": anisetteData.machineID,
        ]
