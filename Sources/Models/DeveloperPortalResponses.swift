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

struct ListProfilesResponse: Decodable, Sendable {
    let resultCode: Int?
    let provisioningProfiles: [ProvisioningProfile]?
    let userString: String?
    let resultString: String?
}

struct DownloadProfileResponse: Decodable, Sendable {
    let resultCode: Int?
    let provisioningProfile: ProvisioningProfile?
    let userString: String?
    let resultString: String?
}
