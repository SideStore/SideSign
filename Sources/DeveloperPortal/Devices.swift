//
//  Devices.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation

public extension DeveloperPortal {

    func fetchDevices(for team: Team, types: DeviceType = .all, session: Session) async throws -> [Device] {
        debugLog("[SideSign] fetchDevices starting...")
        verboseLog("[SideSign] Team: \(team.name) (\(team.identifier))")

        let response: ListDevicesResponse = try await sendRequest(url: Constants.URLs.listDevices, session: session, team: team)

        let devices = (response.devices ?? []).filter { types.contains($0.type) }

        debugLog("[SideSign] fetchDevices completed with \(devices.count) device(s)")
        if !devices.isEmpty {
            let list = devices.enumerated().map { "  \($0.offset + 1). \($0.element.name) (\($0.element.identifier))" }.joined(separator: "\n")
            verboseLog("[SideSign] Devices (\(devices.count)):\n\(list)")
        } else {
            verboseLog("[SideSign] Devices: []")
        }
        return devices
    }

    func registerDevice(name: String,
                        identifier: String,
                        type: DeviceType,
                        team: Team,
                        session: Session) async throws -> Device
    {
        debugLog("[SideSign] registerDevice starting...")
        verboseLog("[SideSign] Name: '\(name)', Identifier: '\(identifier)', Type: \(type), Team: \(team.name)")

        var parameters = [
            "deviceNumber": identifier,
            "name": name
        ]

        if type.contains(.iPhone) || type.contains(.iPad) {
            parameters["DTDK_Platform"] = "ios"
        } else if type.contains(.appleTV) {
            parameters["DTDK_Platform"] = "tvos"
            parameters["subPlatform"] = "tvOS"
        }

        let response: DeviceResponse = try await sendRequest(
            url: Constants.URLs.addDevice,
            additionalParameters: parameters,
            session: session,
            team: team,
            resultCodeHandler: { code, message in
                switch code {
                case DeveloperPortalResultCodes.deviceAlreadyRegistered:
                    debugLog("[SideSign] registerDevice: device already registered (\(code)): \(message)")
                    return DeveloperPortalError.deviceAlreadyRegistered(cause: message)
                default: return nil
                }
            }
        )

        guard let device = response.device else {
            debugLog("[SideSign] registerDevice error: Missing registered device in response")
            throw ServerError.badServerResponse(reason: "Missing registered device in response", jsonPayload: "")
        }

        debugLog("[SideSign] registerDevice succeeded")
        verboseLog("[SideSign] Registered: \(device.name) (\(device.identifier))")
        return device
    }

    func updateDevice(_ device: Device, team: Team, session: Session) async throws -> Device {
        debugLog("[SideSign] updateDevice starting...")
        verboseLog("[SideSign] Name: '\(device.name)', Identifier: '\(device.identifier)', Team: \(team.name)")

        var parameters = [
            "name": device.name,
            "deviceNumber": device.identifier
        ]
        if let deviceID = device.deviceID {
            parameters["deviceId"] = deviceID
        }
        if let status = device.status {
            parameters["status"] = status
        }

        let response: DeviceResponse = try await sendRequest(
            url: Constants.URLs.updateDevice,
            additionalParameters: parameters,
            session: session,
            team: team
        )

        let updatedDevice = response.device ?? device
        debugLog("[SideSign] updateDevice succeeded")
        return updatedDevice
    }

    func disableDevice(_ device: Device, team: Team, session: Session) async throws -> Device {
        debugLog("[SideSign] disableDevice starting...")
        verboseLog("[SideSign] Identifier: '\(device.identifier)', Team: \(team.name)")

        var parameters = [
            "deviceNumber": device.identifier,
            "status": "d"
        ]
        if let deviceID = device.deviceID {
            parameters["deviceId"] = deviceID
        }
        if !device.name.isEmpty {
            parameters["name"] = device.name
        }

        let _: EmptyResponse = try await sendRequest(
            url: Constants.URLs.disableDevice,
            additionalParameters: parameters,
            session: session,
            team: team
        )

        var updated = device
        updated.status = "d"
        debugLog("[SideSign] disableDevice succeeded")
        return updated
    }

    func deleteDevice(_ device: Device, team: Team, session: Session) async throws -> Bool {
        debugLog("[SideSign] deleteDevice starting...")
        verboseLog("[SideSign] Identifier: '\(device.identifier)', Team: \(team.name)")

        var parameters = [
            "deviceNumber": device.identifier
        ]
        if let deviceID = device.deviceID {
            parameters["deviceId"] = deviceID
        }

        let _: EmptyResponse = try await sendRequest(
            url: Constants.URLs.deleteDevice,
            additionalParameters: parameters,
            session: session,
            team: team
        )

        debugLog("[SideSign] deleteDevice completed")
        return true
    }
}
