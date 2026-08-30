//
//  AnisetteData.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation

public struct AnisetteData: Sendable, Codable, Equatable, Hashable {
    public var machineID: String
    public var oneTimePassword: String
    public var localUserID: String
    public var routingInfo: UInt64
    public var deviceUniqueIdentifier: String
    public var deviceSerialNumber: String
    public var deviceDescription: String
    public var date: Date
    public var locale: Locale
    public var timeZone: TimeZone

    public init(
        machineID: String,
        oneTimePassword: String,
        localUserID: String,
        routingInfo: UInt64,
        deviceUniqueIdentifier: String,
        deviceSerialNumber: String,
        deviceDescription: String,
        date: Date,
        locale: Locale,
        timeZone: TimeZone
    ) {
        self.machineID = machineID
        self.oneTimePassword = oneTimePassword
        self.localUserID = localUserID
        self.routingInfo = routingInfo
        self.deviceUniqueIdentifier = deviceUniqueIdentifier
        self.deviceSerialNumber = deviceSerialNumber
        self.deviceDescription = deviceDescription
        self.date = date
        self.locale = locale
        self.timeZone = timeZone
    }
}
