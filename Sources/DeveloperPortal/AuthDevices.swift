//
//  AuthDevices.swift
//  SideSign
//
//  Created by Magesh K on 03/09/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation

public extension DeveloperPortal {

    func fetchAuthDevices(session: Session) async throws -> [AuthDevice] {
        debugLog("[SideSign] fetchAuthDevices starting for dsid: \(session.dsid)...")

        // 1. Try idmsa devices endpoint
        var request = URLRequest(url: Constants.URLs.appleAuthDevices)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue(Constants.authKitUserAgent, forHTTPHeaderField: "User-Agent")
        request.setValue(session.authToken, forHTTPHeaderField: "X-Apple-Session-Token")
        request.setValue("X-Apple-GS-Token \(session.authToken)", forHTTPHeaderField: "Authorization")
        request.setValue(session.anisetteData.oneTimePassword, forHTTPHeaderField: "X-Apple-I-MD")
        request.setValue(session.anisetteData.machineID, forHTTPHeaderField: "X-Apple-I-MD-M")
        request.setValue(String(session.anisetteData.routingInfo), forHTTPHeaderField: "X-Apple-I-MD-RINFO")
        request.setValue(session.anisetteData.localUserID, forHTTPHeaderField: "X-Apple-I-MD-LU")

        let clientInfoDict: [String: String] = [
            "deviceUdid": session.anisetteData.machineID,
            "appIdKey": Constants.appIDKey
        ]
        if let clientInfoData = try? JSONSerialization.data(withJSONObject: clientInfoDict),
           let clientInfoStr = String(data: clientInfoData, encoding: .utf8) {
            request.setValue(clientInfoStr, forHTTPHeaderField: "X-Apple-I-FD-Client-Info")
        }

        do {
            let (data, response) = try await self.session.data(for: request)
            if let httpResp = response as? HTTPURLResponse, httpResp.isSuccess {
                if let jsonArray = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] {
                    let devices: [AuthDevice] = jsonArray.compactMap { dict in
                        guard let id = (dict["id"] as? String) ?? (dict["deviceId"] as? String) else { return nil }
                        let name = dict["name"] as? String ?? dict["modelDisplayName"] as? String ?? "Device"
                        let model = dict["model"] as? String ?? dict["modelSmallPhotoURL1x"] as? String
                        let modelDisplayName = dict["modelDisplayName"] as? String ?? dict["modelLargePhotoURL1x"] as? String
                        let osVersion = dict["osVersion"] as? String ?? dict["os"] as? String
                        let serial = dict["serialNumber"] as? String
                        let current = dict["currentDevice"] as? Bool ?? false
                        return AuthDevice(
                            id: id,
                            name: name,
                            model: model,
                            modelDisplayName: modelDisplayName,
                            osVersion: osVersion,
                            serialNumber: serial,
                            isCurrentDevice: current
                        )
                    }
                    debugLog("[SideSign] fetchAuthDevices parsed \(devices.count) device(s) via idmsa")
                    return devices
                }
            }
        } catch {
            debugLog("[SideSign] idmsa fetchAuthDevices failed, trying GSA/GrandSlam: \(error.localizedDescription)")
        }

        // 2. Fallback: GrandSlam / GsService2 listDevices
        let parameters: [String: any Sendable] = [
            "c": "com.apple.gs.idms.devices",
            "o": "listDevices",
            "u": session.dsid
        ]
        let responseDict = try await sendAuthenticationRequest(parameters: parameters, anisetteData: session.anisetteData)
        if let devicesList = responseDict["devices"] as? [[String: Any]] {
            return devicesList.compactMap { dict in
                guard let id = (dict["id"] as? String) ?? (dict["deviceId"] as? String) else { return nil }
                let name = dict["name"] as? String ?? "Device"
                let model = dict["model"] as? String
                let modelDisplayName = dict["modelDisplayName"] as? String
                let osVersion = dict["osVersion"] as? String
                let serial = dict["serialNumber"] as? String
                let current = dict["currentDevice"] as? Bool ?? false
                return AuthDevice(
                    id: id,
                    name: name,
                    model: model,
                    modelDisplayName: modelDisplayName,
                    osVersion: osVersion,
                    serialNumber: serial,
                    isCurrentDevice: current
                )
            }
        }

        return []
    }

    func removeAuthDevice(id: String, session: Session) async throws -> Bool {
        debugLog("[SideSign] removeAuthDevice starting for id: \(id)...")

        // 1. Try idmsa DELETE endpoint
        guard let deleteURL = URL(string: "\(Constants.URLs.appleAuthDevices.absoluteString)/\(id)") else {
            throw DeveloperPortalError.invalidParameters(cause: "Invalid device ID URL for '\(id)'")
        }
        var request = URLRequest(url: deleteURL)
        request.httpMethod = "DELETE"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue(Constants.authKitUserAgent, forHTTPHeaderField: "User-Agent")
        request.setValue(session.authToken, forHTTPHeaderField: "X-Apple-Session-Token")
        request.setValue("X-Apple-GS-Token \(session.authToken)", forHTTPHeaderField: "Authorization")
        request.setValue(session.anisetteData.oneTimePassword, forHTTPHeaderField: "X-Apple-I-MD")
        request.setValue(session.anisetteData.machineID, forHTTPHeaderField: "X-Apple-I-MD-M")
        request.setValue(String(session.anisetteData.routingInfo), forHTTPHeaderField: "X-Apple-I-MD-RINFO")
        request.setValue(session.anisetteData.localUserID, forHTTPHeaderField: "X-Apple-I-MD-LU")

        do {
            let (_, response) = try await self.session.data(for: request)
            if let httpResp = response as? HTTPURLResponse, httpResp.isSuccess {
                debugLog("[SideSign] removeAuthDevice succeeded via idmsa DELETE")
                return true
            }
        } catch {
            debugLog("[SideSign] idmsa removeAuthDevice failed, trying GSA/GrandSlam: \(error.localizedDescription)")
        }

        // 2. Fallback: GrandSlam removeDevice
        let parameters: [String: any Sendable] = [
            "c": "com.apple.gs.idms.devices",
            "o": "removeDevice",
            "deviceId": id,
            "u": session.dsid
        ]
        let responseDict = try await sendAuthenticationRequest(parameters: parameters, anisetteData: session.anisetteData)
        let success = (responseDict["status"] as? Int == 0) || (responseDict["ec"] as? Int == 0) || responseDict["Status"] != nil
        debugLog("[SideSign] removeAuthDevice GSA result: \(success)")
        return success
    }
}
