//
//  Profiles.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation

public extension DeveloperPortal {

    func fetchProvisioningProfiles(includeTeamProfiles: Bool = true, for team: Team, session: Session) async throws -> [ListedProvisioningProfile] {
        debugLog("[SideSign] fetchProvisioningProfiles starting (includeTeamProfiles=\(includeTeamProfiles))...")
        verboseLog("[SideSign] Team: \(team.name)")

        var parameters: [String: any Sendable] = [:]
        if includeTeamProfiles {
            parameters["includeTeamProfiles"] = true
        }

        do {
            let response: ListedProfileResponse = try await sendRequest(
                url: Constants.URLs.listProvisioningProfiles,
                additionalParameters: parameters,
                session: session,
                team: team
            )

            guard let profiles = response.provisioningProfiles else {
                debugLog("[SideSign] fetchProvisioningProfiles completed with 0 profiles (provisioningProfiles was nil)")
                verboseLog("[SideSign] Profiles: []")
                return []
            }

            debugLog("[SideSign] fetchProvisioningProfiles completed with \(profiles.count) profile(s)")
            if !profiles.isEmpty {
                let list = profiles.enumerated().map { "  \($0.offset + 1). \($0.element.name) (\($0.element.bundleIdentifier ?? "none"))\($0.element.isTeamProfile == true ? " [Team Profile]" : "")" }.joined(separator: "\n")
                verboseLog("[SideSign] Profiles (\(profiles.count)):\n\(list)")
            } else {
                verboseLog("[SideSign] Profiles: []")
            }
            return profiles
        } catch {
            debugLog("[SideSign] fetchProvisioningProfiles failed: \(error)")
            throw error
        }
    }

    func createProvisioningProfile(name: String,
                                  appID: AppID,
                                  certificateIDs: [String],
                                  deviceIDs: [String],
                                  subPlatform: String? = nil,
                                  team: Team,
                                  session: Session) async throws -> ProvisioningProfile
    {
        debugLog("[SideSign] createProvisioningProfile starting...")
        verboseLog("[SideSign] Name: \(name), AppID: \(appID.bundleIdentifier), Team: \(team.name)")

        var parameters: [String: any Sendable] = [
            "provisioningProfileName": name,
            "appIdId": appID.identifier,
            "distributionType": "limited",
            "certificateIds": certificateIDs,
            "deviceIds": deviceIDs
        ]
        if let subPlatform = subPlatform {
            parameters["subPlatform"] = subPlatform
        }

        do {
            let response: ProfileResponse = try await sendRequest(
                url: Constants.URLs.createProvisioningProfile,
                additionalParameters: parameters,
                session: session,
                team: team
            )

            guard let createdProfile = try response.provisioningProfile?.toProvisioningProfile() else {
                debugLog("[SideSign] createProvisioningProfile error: Missing provisioning profile in create response")
                throw ServerError.badServerResponse(reason: "Missing provisioning profile in create response", jsonPayload: "")
            }

            debugLog("[SideSign] createProvisioningProfile succeeded")
            verboseLog("[SideSign] Created: \(createdProfile.name) (\(createdProfile.bundleIdentifier))")
            return createdProfile
        } catch {
            debugLog("[SideSign] createProvisioningProfile failed: \(error)")
            throw error
        }
    }

    func updateProvisioningProfile(profileID: String,
                                  name: String,
                                  appIDId: String,
                                  certificateIDs: [String],
                                  deviceIDs: [String],
                                  subPlatform: String? = nil,
                                  team: Team,
                                  session: Session) async throws -> ProvisioningProfile
    {
        debugLog("[SideSign] updateProvisioningProfile starting...")
        verboseLog("[SideSign] ProfileID: \(profileID), Name: \(name), AppID: \(appIDId), Team: \(team.name)")

        var parameters: [String: any Sendable] = [
            "provisioningProfileId": profileID,
            "provisioningProfileName": name,
            "appIdId": appIDId,
            "distributionType": "limited",
            "certificateIds": certificateIDs,
            "deviceIds": deviceIDs
        ]
        if let subPlatform = subPlatform {
            parameters["subPlatform"] = subPlatform
        }

        do {
            let response: ProfileResponse = try await sendRequest(
                url: Constants.URLs.regenProvisioningProfile,
                additionalParameters: parameters,
                session: session,
                team: team
            )

            guard let updatedProfile = try response.provisioningProfile?.toProvisioningProfile() else {
                debugLog("[SideSign] updateProvisioningProfile error: Missing provisioning profile in regen response")
                throw ServerError.badServerResponse(reason: "Missing provisioning profile in regen response", jsonPayload: "")
            }

            debugLog("[SideSign] updateProvisioningProfile succeeded")
            verboseLog("[SideSign] Updated: \(updatedProfile.name) (\(updatedProfile.bundleIdentifier))")
            return updatedProfile
        } catch {
            debugLog("[SideSign] updateProvisioningProfile failed: \(error)")
            throw error
        }
    }

    func downloadProvisioningProfile(profileID: String,
                                     team: Team,
                                     session: Session) async throws -> ProvisioningProfile
    {
        debugLog("[SideSign] downloadProvisioningProfile(profileID:) starting...")
        verboseLog("[SideSign] ProfileID: \(profileID), Team: \(team.name)")

        let parameters: [String: any Sendable] = ["provisioningProfileId": profileID]

        do {
            let response: ProfileResponse = try await sendRequest(
                url: Constants.URLs.downloadManualProvisioningProfile,
                additionalParameters: parameters,
                session: session,
                team: team
            )

            guard let downloadedProfile = try response.provisioningProfile?.toProvisioningProfile() else {
                debugLog("[SideSign] downloadProvisioningProfile(profileID:) error: Missing provisioning profile in download response")
                throw ServerError.badServerResponse(reason: "Missing provisioning profile in download response", jsonPayload: "")
            }

            debugLog("[SideSign] downloadProvisioningProfile(profileID:) succeeded")
            verboseLog("[SideSign] Downloaded: \(downloadedProfile.name) (\(downloadedProfile.bundleIdentifier))")
            return downloadedProfile
        } catch {
            debugLog("[SideSign] downloadProvisioningProfile(profileID:) failed: \(error)")
            throw error
        }
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

        do {
            let response: ProfileResponse = try await sendRequest(
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

            guard let downloadedProfile = try response.provisioningProfile?.toProvisioningProfile() else {
                debugLog("[SideSign] downloadProvisioningProfile error: Missing provisioning profile in download response")
                throw ServerError.badServerResponse(reason: "Missing provisioning profile in download response", jsonPayload: "")
            }

            debugLog("[SideSign] downloadProvisioningProfile succeeded")
            verboseLog("[SideSign] Downloaded: \(downloadedProfile.name) (\(downloadedProfile.bundleIdentifier))")
            return downloadedProfile
        } catch {
            debugLog("[SideSign] downloadProvisioningProfile failed: \(error)")
            throw error
        }
    }

    func deleteProvisioningProfile(_ profile: ListedProvisioningProfile, team: Team, session: Session) async throws -> Bool {
        guard let profileID = profile.identifier else {
            debugLog("[SideSign] deleteProvisioningProfile error: Profile identifier is missing")
            throw DeveloperPortalError.invalidProvisioningProfileIdentifier(profile.name)
        }

        debugLog("[SideSign] deleteProvisioningProfile starting...")
        verboseLog("[SideSign] ProfileID: \(profileID), Team: \(team.name)")

        let parameters = ["provisioningProfileId": profileID]

        do {
            let _: EmptyResponse = try await sendRequest(url: Constants.URLs.deleteProvisioningProfile, additionalParameters: parameters, session: session, team: team)
            debugLog("[SideSign] deleteProvisioningProfile succeeded")
            verboseLog("[SideSign] Deleted: \(profileID)")
            return true
        } catch {
            debugLog("[SideSign] deleteProvisioningProfile failed: \(error)")
            throw error
        }
    }

    func deleteProvisioningProfile(_ profile: ProvisioningProfile, team: Team, session: Session) async throws -> Bool {
        guard let profileID = profile.identifier else {
            debugLog("[SideSign] deleteProvisioningProfile error: Profile identifier is missing")
            throw DeveloperPortalError.invalidProvisioningProfileIdentifier(profile.name)
        }

        debugLog("[SideSign] deleteProvisioningProfile starting...")
        verboseLog("[SideSign] ProfileID: \(profileID), Team: \(team.name)")

        let parameters = ["provisioningProfileId": profileID]

        do {
            let _: EmptyResponse = try await sendRequest(url: Constants.URLs.deleteProvisioningProfile, additionalParameters: parameters, session: session, team: team)
            debugLog("[SideSign] deleteProvisioningProfile succeeded")
            verboseLog("[SideSign] Deleted: \(profileID)")
            return true
        } catch {
            debugLog("[SideSign] deleteProvisioningProfile failed: \(error)")
            throw error
        }
    }
}
