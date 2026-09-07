//
//  AnisetteData.swift
//  SideSign
//
//  Created by Magesh K on 07/09/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
import AnisetteKit

public struct AnisetteData: Sendable, Codable, Equatable, Hashable {
    public var machineID: String
    public var oneTimePassword: String
    public var localUserID: String
    public var routingInfo: String
    public var deviceID: String
    public var serialNumber: String
    public var clientInfo: String
    public var userAgent: String
    public var clientTime: String
    public var locale: String
    public var timeZone: String

    public var deviceUniqueIdentifier: String {
        get { deviceID }
        set { deviceID = newValue }
    }

    public var deviceDescription: String {
        get { clientInfo }
        set { clientInfo = newValue }
    }

    public var deviceSerialNumber: String {
        get { serialNumber }
        set { serialNumber = newValue }
    }

    public init(
        machineID: String,
        oneTimePassword: String,
        localUserID: String,
        routingInfo: String,
        deviceID: String,
        serialNumber: String,
        clientInfo: String,
        userAgent: String,
        clientTime: String,
        locale: String,
        timeZone: String
    ) {
        self.machineID = machineID
        self.oneTimePassword = oneTimePassword
        self.localUserID = localUserID
        self.routingInfo = routingInfo
        self.deviceID = deviceID
        self.serialNumber = serialNumber
        self.clientInfo = clientInfo
        self.userAgent = userAgent
        self.clientTime = clientTime
        self.locale = locale
        self.timeZone = timeZone
    }

    public func toRequestHeaders() -> AnisetteRequestHeaders {
        AnisetteRequestHeaders().with {
            $0.machineID = self.machineID
            $0.oneTimePassword = self.oneTimePassword
            $0.localUserID = self.localUserID
            $0.routingInfo = self.routingInfo
            $0.deviceID = self.deviceID
            $0.serialNumber = self.serialNumber
            $0.clientInfo = self.clientInfo
            $0.userAgent = self.userAgent
            $0.clientTime = self.clientTime
            $0.locale = self.locale
            $0.timeZone = self.timeZone
        }
    }
}
