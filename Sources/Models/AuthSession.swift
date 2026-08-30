//
//  AuthSession.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation

public struct AuthSession: Sendable, Codable, Equatable {
    public let account: Account
    public let session: Session

    public init(account: Account, session: Session) {
        self.account = account
        self.session = session
    }
}
