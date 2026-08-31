//
//  AppIDs.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation

public extension DeveloperPortal {

    func fetchAppIDs(for team: Team, session: Session) async throws -> [AppID] {
        debugLog("[SideSign] fetchAppIDs starting...")
        verboseLog("[SideSign] Team: \(team.name)")

        let response: ListAppIDsResponse = try await sendRequest(url: Constants.URLs.listAppIDs, session: session, team: team)

        let appIDs = response.appIds ?? []

        debugLog("[SideSign] fetchAppIDs completed with \(appIDs.count) App ID(s)")
        if !appIDs.isEmpty {
            let list = appIDs.enumerated().map { "  \($0.offset + 1). \($0.element.name) (\($0.element.bundleIdentifier))" }.joined(separator: "\n")
            verboseLog("[SideSign] AppIDs (\(appIDs.count)):\n\(list)")
        } else {
            verboseLog("[SideSign] AppIDs: []")
        }
        return appIDs
    }

    func addAppID(withName name: String, bundleIdentifier: String, team: Team, session: Session) async throws -> AppID {
        debugLog("[SideSign] addAppID starting...")
        verboseLog("[SideSign] Name: '\(name)', BundleID: '\(bundleIdentifier)', Team: \(team.name)")

        let parameters = [
            "name": name,
            "identifier": bundleIdentifier
        ]

        let response: AppIDResponse = try await sendRequest(
            url: Constants.URLs.addAppID,
            additionalParameters: parameters,
            session: session,
            team: team,
            resultCodeHandler: { code, message in
                switch code {
                case DeveloperPortalResultCodes.bundleIdentifierUnavailable:
                    debugLog("[SideSign] addAppID error: Bundle identifier unavailable (\(code)): \(message)")
                    return DeveloperPortalError.bundleIdentifierUnavailable(cause: message)
                case DeveloperPortalResultCodes.maximumAppIDLimitReached:
                    debugLog("[SideSign] addAppID error: Maximum App ID limit reached (\(code)): \(message)")
                    return DeveloperPortalError.maximumAppIDLimitReached(cause: message)
                default: return nil
                }
            }
        )

        guard let createdAppID = response.appId else {
            debugLog("[SideSign] addAppID error: Missing appId in response")
            throw ServerError.badServerResponse(reason: "Missing appId in response", jsonPayload: "")
        }

        debugLog("[SideSign] addAppID succeeded")
        verboseLog("[SideSign] Created: \(createdAppID.name) (\(createdAppID.bundleIdentifier))")
        return createdAppID
    }

    func updateAppID(_ appID: AppID, team: Team, session: Session) async throws -> AppID {
        debugLog("[SideSign] updateAppID starting...")
        verboseLog("[SideSign] AppID: \(appID.bundleIdentifier), Team: \(team.name)")

        var parameters: [String: any Sendable] = [
            "appIdId": appID.identifier
        ]

        for (feature, value) in appID.features {
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.lowercased() == "true" {
                parameters[feature.rawValue] = true
            } else if trimmed.lowercased() == "false" {
                parameters[feature.rawValue] = false
            } else {
                parameters[feature.rawValue] = trimmed
            }
        }

        let response: AppIDResponse = try await sendRequest(url: Constants.URLs.updateAppID, additionalParameters: parameters, session: session, team: team)

        guard let updatedAppID = response.appId else {
            debugLog("[SideSign] updateAppID error: Missing appId in response")
            throw ServerError.badServerResponse(reason: "Missing appId in update response", jsonPayload: "")
        }

        debugLog("[SideSign] updateAppID succeeded")
        verboseLog("[SideSign] Updated: \(updatedAppID.name) (\(updatedAppID.bundleIdentifier))")
        return updatedAppID
    }

    func deleteAppID(_ appID: AppID, for team: Team, session: Session) async throws -> Bool {
        debugLog("[SideSign] deleteAppID starting...")
        verboseLog("[SideSign] AppID: \(appID.name) (\(appID.bundleIdentifier)), Team: \(team.name)")

        let parameters = ["appIdId": appID.identifier]

        let _: EmptyResponse = try await sendRequest(url: Constants.URLs.deleteAppID, additionalParameters: parameters, session: session, team: team)
        debugLog("[SideSign] deleteAppID completed")
        return true
    }
}
