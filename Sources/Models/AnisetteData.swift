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
        date: Date = Date(),
        locale: Locale = .current,
        timeZone: TimeZone = .current
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

    public init?(json: [String: String]) {
        guard
            let machineID = json["machineID"],
            let otp = json["oneTimePassword"],
            let localUserID = json["localUserID"],
            let routingInfoString = json["routingInfo"],
            let deviceUID = json["deviceUniqueIdentifier"],
            let serial = json["deviceSerialNumber"],
            let desc = json["deviceDescription"],
            let dateString = json["date"],
            let localeID = json["locale"],
            let tzID = json["timeZone"]
        else { return nil }

        let formatter = ISO8601DateFormatter()
        guard let date = formatter.date(from: dateString) else { return nil }

        let cleanLocaleID = localeID.components(separatedBy: "@").first ?? localeID
        let locale = Locale(identifier: cleanLocaleID)
        let tz = TimeZone(abbreviation: tzID) ?? .current

        self.init(
            machineID: machineID,
            oneTimePassword: otp,
            localUserID: localUserID,
            routingInfo: UInt64(routingInfoString) ?? 0,
            deviceUniqueIdentifier: deviceUID,
            deviceSerialNumber: serial,
            deviceDescription: desc,
            date: date,
            locale: locale,
            timeZone: tz
        )
    }

    public func json() -> [String: String] {
        let formatter = ISO8601DateFormatter()
        return [
            "machineID": machineID,
            "oneTimePassword": oneTimePassword,
            "localUserID": localUserID,
            "routingInfo": String(routingInfo),
            "deviceUniqueIdentifier": deviceUniqueIdentifier,
            "deviceSerialNumber": deviceSerialNumber,
            "deviceDescription": deviceDescription,
            "date": formatter.string(from: date),
            "locale": locale.identifier.components(separatedBy: "@").first ?? "en_US",
            "timeZone": timeZone.abbreviation() ?? TimeZone.current.abbreviation() ?? "PST"
        ]
    }
}
