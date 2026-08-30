//
//  Certificates.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
import CodeSignKit

public extension DeveloperPortal {

    func fetchCertificates(for team: Team, session: Session) async throws -> [X509Certificate] {
        debugLog("[SideSign] fetchCertificates starting...")
        verboseLog("[SideSign] Team: \(team.name) (\(team.identifier))")

        let response: ListCertificatesResponse = try await sendRequest(url: Constants.URLs.listCertificates, session: session, team: team)

        let certificates = (response.certificates ?? []).compactMap { $0.toCertificate() }

        debugLog("[SideSign] fetchCertificates completed with \(certificates.count) certificate(s)")
        if !certificates.isEmpty {
            let list = certificates.enumerated().map { "  \($0.offset + 1). \($0.element.name) (\($0.element.serialNumber))" }.joined(separator: "\n")
            verboseLog("[SideSign] Certificates (\(certificates.count)):\n\(list)")
        } else {
            verboseLog("[SideSign] Certificates: []")
        }
        return certificates
    }

    func addCertificate(machineName: String, to team: Team, session: Session) async throws -> KeyStore {
        debugLog("[SideSign] addCertificate starting...")
        verboseLog("[SideSign] MachineName: '\(machineName)', Team: \(team.name)")

        let certRequest: CertificateRequest
        do {
            certRequest = try CertificateRequest(machineName: machineName)
        } catch {
            debugLog("[SideSign] addCertificate error: Failed to generate CSR / RSA keypair: \(error)")
            throw error
        }

        let csrString = String(decoding: certRequest.csrData, as: UTF8.self)

        let parameters = [
            "csrContent": csrString,
            "machineName": machineName,
            "machineId": UUID().uuidString.uppercased()
        ]

        let response: AddCertificateResponse = try await sendRequest(
            url: Constants.URLs.submitCSR,
            additionalParameters: parameters,
            session: session,
            team: team,
            resultCodeHandler: { code, message in
                switch code {
                case DeveloperPortalResultCodes.invalidCertificateRequest:
                    return DeveloperPortalError.invalidCertificateRequest(cause: message)
                case DeveloperPortalResultCodes.maximumCertificatesReachedAlternate, DeveloperPortalResultCodes.maximumCertificatesReached:
                    debugLog("[SideSign] addCertificate: maximum certificates reached (\(code)): \(message)")
                    return DeveloperPortalError.tooManyCertificates(cause: message)
                default: return nil
                }
            }
        )

        let cert: X509Certificate
        if let directCert = response.certRequest?.toCertificate() {
            cert = directCert
        } else {
            let serial = response.certRequest?.serialNumber
            let certId = response.certRequest?.certificateId ?? response.certRequest?.certRequestId
            let allCerts = try await fetchCertificates(for: team, session: session)

            guard let matchedCert = allCerts.first(where: {
                if let serial, $0.serialNumber.caseInsensitiveCompare(serial) == .orderedSame { return true }
                if let certId, $0.identifier == certId { return true }
                return false
            }) ?? allCerts.first else {
                debugLog("[SideSign] addCertificate error: Failed to retrieve new certificate from Developer Portal")
                throw ServerError.badServerResponse(reason: "Failed to retrieve new certificate from Developer Portal", jsonPayload: "")
            }
            cert = matchedCert
        }

        debugLog("[SideSign] addCertificate succeeded")
        verboseLog("[SideSign] SerialNumber: \(cert.serialNumber)")
        return KeyStore(certificate: cert, privateKey: certRequest.privateKey)
    }

    func revokeCertificate(_ certificate: X509Certificate, for team: Team, session: Session) async throws -> Bool {
        let certIdentifier = certificate.identifier ?? certificate.serialNumber
        debugLog("[SideSign] revokeCertificate starting...")
        verboseLog("[SideSign] Name: '\(certificate.name)', ID: '\(certIdentifier)', SN: \(certificate.serialNumber), Team: \(team.name)")

        let url = URL(string: "certificates/\(certIdentifier)", relativeTo: servicesBaseURL)!
        var request = URLRequest(url: url)
        request.httpMethod = "DELETE"

        let _: EmptyResponse = try await sendServicesRequest(request, additionalParameters: nil, session: session, team: team)
        debugLog("[SideSign] revokeCertificate succeeded")
        verboseLog("[SideSign] Revoked Certificate: \(certIdentifier)")
        return true
    }
}
