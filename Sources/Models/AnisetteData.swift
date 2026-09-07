//
//  AnisetteData.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
import AnisetteKit

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

    public init?(headers: AnisetteHeaders, defaultDeviceID: String? = nil) {
        guard let machineID = headers.machineID,
              let otp = headers.oneTimePassword,
              let routingInfoStr = headers.routingInfo,
              let routingInfo = UInt64(routingInfoStr) else {
            return nil
        }

        self.machineID = machineID
        self.oneTimePassword = otp
        self.localUserID = headers.localUserID ?? AnisetteConstants.defaultLocalUserID
        self.routingInfo = routingInfo
        self.deviceUniqueIdentifier = headers.deviceID ?? defaultDeviceID ?? ""
        self.deviceSerialNumber = headers.serialNumber ?? AnisetteConstants.defaultSerialNumber
        self.deviceDescription = headers.clientInfo ?? AnisetteConstants.defaultClientInfo
        self.date = headers.date ?? Date()
        self.locale = headers.locale.flatMap { Locale(identifier: $0) } ?? .current
        self.timeZone = headers.timeZone.flatMap { TimeZone(abbreviation: $0) ?? TimeZone(identifier: $0) } ?? .current
    }

    public var headers: AnisetteHeaders {
        AnisetteHeaders().with {
            $0.machineID = machineID
            $0.oneTimePassword = oneTimePassword
            $0.localUserID = localUserID
            $0.routingInfo = String(routingInfo)
            $0.deviceID = deviceUniqueIdentifier
            $0.serialNumber = deviceSerialNumber
            $0.clientInfo = deviceDescription
            $0.date = date
            $0.locale = locale.identifier.components(separatedBy: "@").first ?? "en_US"
            $0.timeZone = AnisetteKit.safeTimeZoneAbbreviation(for: timeZone, date: date)
        }
    }
}
