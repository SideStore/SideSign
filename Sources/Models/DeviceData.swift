//
//  DeviceData.swift
//  SideSign
//
//  Created by Magesh K on 01/09/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation

public struct DeviceData: Sendable, Codable, Equatable {
    public let identifier: UUID
    public let adiBlob: Data
    public let machineID: String?
    public let localUserID: String?

    public init(
        identifier: UUID,
        adiBlob: Data,
        machineID: String? = nil,
        localUserID: String? = nil
    ) {
        self.identifier = identifier
        self.adiBlob = adiBlob
        self.machineID = machineID
        self.localUserID = localUserID
    }
}
