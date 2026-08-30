//
//  Profiles.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation

public extension DeveloperPortal {

    func fetchProvisioningProfiles(for team: Team, session: Session) async throws -> [ProvisioningProfile] {
        debugLog("[SideSign] fetchProvisioningProfiles starting...")
        verboseLog("[SideSign] Team: \(team.name)")

        let response: ListProfilesResponse = try await sendRequest(url: Constants.URLs.listProvisioningProfiles, session: session, team: team)

        let profiles = response.provisioningProfiles ?? []

        debugLog("[SideSign] fetchProvisioningProfiles completed with \(profiles.count) profile(s)")
        if !profiles.isEmpty {
            let list = profiles.enumerated().map { "  \($0.offset + 1). \($0.element.name) (\($0.element.bundleIdentifier))" }.joined(separator: "\n")
            verboseLog("[SideSign] Profiles (\(profiles.count)):\n\(list)")
        } else {
            verboseLog("[SideSign] Profiles: []")
        }
        return profiles
    }

    func downloadProvisioningProfile(for appID: AppID,
                                     deviceType: DeviceType = .iPhone,
                                     team: Team,
                                     session: Session) async throws -> ProvisioningProfile
    {
        debugLog("[SideSign] downloadProvisioningProfile starting...")
        verboseLog("[SideSign] AppID: \(appID.bundleIdentifier), Team: \(team.name)")

        var parameters = ["appIdId": appID.identifier]
        if deviceType.contains(.appleTV) {
            parameters["subPlatform"] = "tvOS"
        }

        let response: DownloadProfileResponse = try await sendRequest(
            url: Constants.URLs.downloadProvisioningProfile,
            additionalParameters: parameters,
            session: session,
            team: team,
            resultCodeHandler: { code, message in
                if code == DeveloperPortalResultCodes.appIDDoesNotExistAlternate || code == DeveloperPortalResultCodes.appIDDoesNotExist {
                    return DeveloperPortalError.appIDDoesNotExist(identifier: appID.identifier)
                }
                return nil
            }
        )

        guard let downloadedProfile = response.provisioningProfile else {
            debugLog("[SideSign] downloadProvisioningProfile error: Missing provisioning profile in download response")
            throw ServerError.badServerResponse(reason: "Missing provisioning profile in download response", jsonPayload: "")
        }

        debugLog("[SideSign] downloadProvisioningProfile succeeded")
        verboseLog("[SideSign] Downloaded: \(downloadedProfile.name) (\(downloadedProfile.bundleIdentifier))")
        return downloadedProfile
    }

    func deleteProvisioningProfile(_ profile: ProvisioningProfile, team: Team, session: Session) async throws -> Bool {
        guard let profileID = profile.identifier else {
            debugLog("[SideSign] deleteProvisioningProfile error: Profile identifier is missing")
            throw DeveloperPortalError.invalidProvisioningProfileIdentifier(profile.name)
        }

        debugLog("[SideSign] deleteProvisioningProfile starting...")
        verboseLog("[SideSign] ProfileID: \(profileID), Team: \(team.name)")

        let parameters = ["provisioningProfileId": profileID]

        let _: EmptyResponse = try await sendRequest(url: Constants.URLs.deleteProvisioningProfile, additionalParameters: parameters, session: session, team: team)
        debugLog("[SideSign] deleteProvisioningProfile succeeded")
        verboseLog("[SideSign] Deleted: \(profileID)")
        return true
    }
}
