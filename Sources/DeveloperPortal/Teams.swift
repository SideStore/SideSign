//
//  Teams.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation

public extension DeveloperPortal {

    func fetchTeams(for account: Account, session: Session) async throws -> [Team] {
        debugLog("[SideSign] fetchTeams starting...")
        verboseLog("[SideSign] Account: \(account.appleID)")

        let response: ListTeamsResponse = try await sendRequest(url: Constants.URLs.listTeams, session: session)

        let teams = (response.teams ?? []).map { team in
            var mutable = team
            mutable.account = account
            return mutable
        }

        debugLog("[SideSign] fetchTeams completed with \(teams.count) team(s)")
        if !teams.isEmpty {
            let list = teams.enumerated().map { "  \($0.offset + 1). \($0.element.name) (\($0.element.identifier))" }.joined(separator: "\n")
            verboseLog("[SideSign] Teams (\(teams.count)):\n\(list)")
        } else {
            verboseLog("[SideSign] Teams: []")
        }

        if teams.isEmpty {
            debugLog("[SideSign] fetchTeams error: No teams found for account")
            throw DeveloperPortalError.noTeams
        }
        return teams
    }
}
