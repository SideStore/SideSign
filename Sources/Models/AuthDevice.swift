//
//  AuthDevice.swift
//  SideSign
//
//  Created by Magesh K on 03/09/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation

public struct AuthDevice: Sendable, Codable, Equatable, Identifiable {
    public let id: String
    public let name: String
    public let model: String?
    public let modelDisplayName: String?
    public let osVersion: String?
    public let serialNumber: String?
    public let isCurrentDevice: Bool

    public init(
        id: String,
        name: String,
        model: String? = nil,
        modelDisplayName: String? = nil,
        osVersion: String? = nil,
        serialNumber: String? = nil,
        isCurrentDevice: Bool = false
    ) {
        self.id = id
        self.name = name
        self.model = model
        self.modelDisplayName = modelDisplayName
        self.osVersion = osVersion
        self.serialNumber = serialNumber
        self.isCurrentDevice = isCurrentDevice
    }
}
