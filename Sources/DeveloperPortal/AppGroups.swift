//
//  AppGroups.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation

public extension DeveloperPortal {

    func fetchAppGroups(for team: Team, session: Session) async throws -> [AppGroup] {
        debugLog("[SideSign] fetchAppGroups starting...")
        verboseLog("[SideSign] Team: \(team.name)")

        let response: ListAppGroupsResponse = try await sendRequest(url: Constants.URLs.listApplicationGroups, session: session, team: team)

        let appGroups = response.applicationGroupList ?? []

        debugLog("[SideSign] fetchAppGroups completed with \(appGroups.count) app group(s)")
        if !appGroups.isEmpty {
            let list = appGroups.enumerated().map { "  \($0.offset + 1). \($0.element.name) (\($0.element.identifier))" }.joined(separator: "\n")
            verboseLog("[SideSign] AppGroups (\(appGroups.count)):\n\(list)")
        } else {
            verboseLog("[SideSign] AppGroups: []")
        }
        return appGroups
    }

    func addAppGroup(name: String, groupIdentifier: String, team: Team, session: Session) async throws -> AppGroup {
        debugLog("[SideSign] addAppGroup starting...")
        verboseLog("[SideSign] Name: '\(name)', GroupID: '\(groupIdentifier)', Team: \(team.name)")

        let parameters = [
            "name": name,
            "identifier": groupIdentifier
        ]

        let response: AppGroupResponse = try await sendRequest(url: Constants.URLs.addApplicationGroup, additionalParameters: parameters, session: session, team: team)

        guard let createdGroup = response.applicationGroup else {
            debugLog("[SideSign] addAppGroup error: Missing applicationGroup in response")
            throw ServerError.badServerResponse(reason: "Missing applicationGroup in response", jsonPayload: "")
        }

        debugLog("[SideSign] addAppGroup succeeded (\(createdGroup.identifier))")
        return createdGroup
    }

    func assignAppGroups(_ appGroups: [AppGroup], to appID: AppID, team: Team, session: Session) async throws -> AppID {
        debugLog("[SideSign] assignAppGroups starting...")
        verboseLog("[SideSign] AppID: \(appID.bundleIdentifier), AppGroups: \(appGroups.map { $0.identifier }), Team: \(team.name)")

        let groupIDs = appGroups.map { $0.groupID }
        let parameters: [String: any Sendable] = [
            "appIdId": appID.identifier,
            "applicationGroups": groupIDs
        ]

        let response: AppIDResponse = try await sendRequest(
            url: Constants.URLs.assignApplicationGroup,
            additionalParameters: parameters,
            session: session,
            team: team,
            resultCodeHandler: { code, message in
                switch code {
                case DeveloperPortalResultCodes.appIDDoesNotExist: 
                    return DeveloperPortalError.appIDDoesNotExist(identifier: appID.identifier)
                case DeveloperPortalResultCodes.appGroupDoesNotExist: 
                    return DeveloperPortalError.appGroupDoesNotExist(message)
                default: return nil
                }
            }
        )

        let updatedAppID = response.appId ?? appID
        debugLog("[SideSign] assignAppGroups succeeded")
        return updatedAppID
    }
}
