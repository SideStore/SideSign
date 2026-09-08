//
//  DeveloperPortalResponses.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
import CodeSignKit

struct EmptyResponse: Decodable, Sendable {
    init() {}
}


struct DeveloperDetails: Decodable, Sendable {
    let email: String?
    let personId: Int64?
    let developerId: String?
    let firstName: String?
    let lastName: String?
    let dsFirstName: String?
    let dsLastName: String?

    func toAccount() -> Account {
        let id: String
        if let personId {
            id = String(personId)
        } else if let developerId {
            id = developerId
        } else {
            id = ""
        }

        return Account(
            appleID: email ?? "",
            identifier: id,
            firstName: firstName ?? dsFirstName ?? "",
            lastName: lastName ?? dsLastName ?? ""
        )
    }
}

struct DeveloperPortalStatusResponse: Decodable, Sendable {
    let resultCode: Int?
    let userString: String?
    let resultString: String?
    let errorString: String?
    let errors: [PortalErrorDetail]?

    struct PortalErrorDetail: Decodable, Sendable {
        let code: String?
        let detail: String?
        let status: String?
        let title: String?
    }
}

struct ViewDeveloperResponse: Decodable, Sendable {
    let resultCode: Int?
    let developer: DeveloperDetails?
    let userString: String?
    let resultString: String?
}

struct ListTeamsResponse: Decodable, Sendable {
    let resultCode: Int?
    let teams: [Team]?
    let userString: String?
    let resultString: String?
}

struct ListDevicesResponse: Decodable, Sendable {
    let resultCode: Int?
    let devices: [Device]?
    let userString: String?
    let resultString: String?
}

struct DeviceResponse: Decodable, Sendable {
    let resultCode: Int?
    let device: Device?
    let userString: String?
    let resultString: String?
}

struct X509CertificateDetails: Decodable, Sendable {
    let certificateId: String?
    let certRequestId: String?
    let certContent: Data?
    let name: String?
    let machineName: String?
    let machineId: String?
    let requesterEmail: String?
    let serialNumber: String?

    enum CodingKeys: String, CodingKey {
        case certificateId, certRequestId, certContent, name, machineName, machineId, requesterEmail
        case serialNumber, serialNum
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.certificateId = try container.decodeIfPresent(String.self, forKey: .certificateId)
        self.certRequestId = try container.decodeIfPresent(String.self, forKey: .certRequestId)
        self.certContent = try container.decodeIfPresent(Data.self, forKey: .certContent)
        self.name = try container.decodeIfPresent(String.self, forKey: .name)
        self.machineName = try container.decodeIfPresent(String.self, forKey: .machineName)
        self.machineId = try container.decodeIfPresent(String.self, forKey: .machineId)
        self.requesterEmail = try container.decodeIfPresent(String.self, forKey: .requesterEmail)
        self.serialNumber = try container.decodeIfPresent(String.self, forKey: .serialNumber)
                             ?? container.decodeIfPresent(String.self, forKey: .serialNum)
    }

    func toCertificate() -> X509Certificate? {
        guard let certContent else { return nil }
        return X509Certificate(
            data: certContent,
            identifier: certificateId ?? certRequestId,
            machineName: machineName,
            machineIdentifier: machineId,
            requesterEmail: requesterEmail
        )
    }
}

struct ListCertificatesResponse: Decodable, Sendable {
    let resultCode: Int?
    let certificates: [X509CertificateDetails]?
    let userString: String?
    let resultString: String?
}

struct AddCertificateResponse: Decodable, Sendable {
    let resultCode: Int?
    let certRequest: X509CertificateDetails?
    let userString: String?
    let resultString: String?
}

struct ListAppIDsResponse: Decodable, Sendable {
    let resultCode: Int?
    let appIds: [AppID]?
    let userString: String?
    let resultString: String?
}

struct AppIDResponse: Decodable, Sendable {
    let resultCode: Int?
    let appId: AppID?
    let userString: String?
    let resultString: String?
}

struct ListAppGroupsResponse: Decodable, Sendable {
    let resultCode: Int?
    let applicationGroupList: [AppGroup]?
    let userString: String?
    let resultString: String?
}

struct AppGroupResponse: Decodable, Sendable {
    let resultCode: Int?
    let applicationGroup: AppGroup?
    let userString: String?
    let resultString: String?
}

public struct AppIDPayload: Sendable, Codable, Equatable, Hashable {
    public let appIdId: String?
    public let identifier: String?
    public let prefix: String?
    public let name: String?

    public init(appIdId: String? = nil, identifier: String? = nil, prefix: String? = nil, name: String? = nil) {
        self.appIdId = appIdId
        self.identifier = identifier
        self.prefix = prefix
        self.name = name
    }
}

public struct ListedProvisioningProfile: Decodable, Sendable, Identifiable, Equatable, Hashable {
    public var id: String { uuid.uuidString }
    public let provisioningProfileId: String?
    public let name: String
    public let status: String?
    public let type: String?
    public let uuid: UUID
    public let dateExpire: Date
    public let appId: AppIDPayload?
    public let deviceIds: [String]?
    public let isFreeProvisioningProfile: Bool?
    public let isTeamProfile: Bool?

    public var identifier: String? { provisioningProfileId }
    public var bundleIdentifier: String? { appId?.identifier }

    enum CodingKeys: String, CodingKey {
        case provisioningProfileId
        case name
        case status
        case type
        case uuid = "UUID"
        case dateExpire
        case appId
        case deviceIds
        case isFreeProvisioningProfile
        case isTeamProfile
    }

    public init(provisioningProfileId: String? = nil,
                name: String,
                status: String? = nil,
                type: String? = nil,
                uuid: UUID,
                dateExpire: Date,
                appId: AppIDPayload? = nil,
                deviceIds: [String]? = nil,
                isFreeProvisioningProfile: Bool? = nil,
                isTeamProfile: Bool? = nil)
    {
        self.provisioningProfileId = provisioningProfileId
        self.name = name
        self.status = status
        self.type = type
        self.uuid = uuid
        self.dateExpire = dateExpire
        self.appId = appId
        self.deviceIds = deviceIds
        self.isFreeProvisioningProfile = isFreeProvisioningProfile
        self.isTeamProfile = isTeamProfile
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.provisioningProfileId = try container.decodeIfPresent(String.self, forKey: .provisioningProfileId)
        self.name = try container.decode(String.self, forKey: .name)
        self.status = try container.decodeIfPresent(String.self, forKey: .status)
        self.type = try container.decodeIfPresent(String.self, forKey: .type)

        let uuidString = try container.decode(String.self, forKey: .uuid)
        guard let parsedUUID = UUID(uuidString: uuidString) else {
            throw DecodingError.dataCorruptedError(forKey: .uuid, in: container, debugDescription: "Invalid UUID format: \(uuidString)")
        }
        self.uuid = parsedUUID

        if let date = try? container.decode(Date.self, forKey: .dateExpire) {
            self.dateExpire = date
        } else if let dateStr = try? container.decode(String.self, forKey: .dateExpire),
                  let date = ISO8601DateFormatter().date(from: dateStr) {
            self.dateExpire = date
        } else {
            throw DecodingError.dataCorruptedError(forKey: .dateExpire, in: container, debugDescription: "Unable to parse dateExpire as Date or ISO8601 string")
        }

        self.appId = try container.decodeIfPresent(AppIDPayload.self, forKey: .appId)
        self.deviceIds = try container.decodeIfPresent([String].self, forKey: .deviceIds)
        self.isFreeProvisioningProfile = try container.decodeIfPresent(Bool.self, forKey: .isFreeProvisioningProfile)
        self.isTeamProfile = try container.decodeIfPresent(Bool.self, forKey: .isTeamProfile)
    }
}

public struct ListedProfileResponse: Decodable, Sendable {
    public let resultCode: Int?
    public let provisioningProfiles: [ListedProvisioningProfile]?
    public let userString: String?
    public let resultString: String?
}

public struct DownloadedProfileDetails: Decodable, Sendable {
    public let provisioningProfileId: String?
    public let name: String?
    public let status: String?
    public let type: String?
    public let uuid: String?
    public let dateExpire: Date?
    public let encodedProfile: Data

    enum CodingKeys: String, CodingKey {
        case provisioningProfileId
        case name
        case status
        case type
        case uuid = "UUID"
        case dateExpire
        case encodedProfile
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.provisioningProfileId = try container.decodeIfPresent(String.self, forKey: .provisioningProfileId)
        self.name = try container.decodeIfPresent(String.self, forKey: .name)
        self.status = try container.decodeIfPresent(String.self, forKey: .status)
        self.type = try container.decodeIfPresent(String.self, forKey: .type)
        self.uuid = try container.decodeIfPresent(String.self, forKey: .uuid)
        self.encodedProfile = try container.decode(Data.self, forKey: .encodedProfile)

        if let date = try? container.decodeIfPresent(Date.self, forKey: .dateExpire) {
            self.dateExpire = date
        } else if let dateStr = try? container.decodeIfPresent(String.self, forKey: .dateExpire) {
            self.dateExpire = ISO8601DateFormatter().date(from: dateStr)
        } else {
            self.dateExpire = nil
        }
    }

    public func toProvisioningProfile() throws -> ProvisioningProfile {
        var profile = try ProvisioningProfile(data: encodedProfile)
        profile.identifier = provisioningProfileId
        return profile
    }
}

public struct ProfileResponse: Decodable, Sendable {
    public let resultCode: Int?
    public let provisioningProfile: DownloadedProfileDetails?
    public let userString: String?
    public let resultString: String?
}
