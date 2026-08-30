//
//  CertificateRequest.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
import CodeSignKit

public struct CertificateRequest: Sendable {
    public var machineName: String
    public var privateKey: Data
    public var csrData: Data

    public init(machineName: String) throws {
        self.machineName = machineName

        let subject = CSRSubject(
            country: "US",
            state: "CA",
            locality: "Los Angeles",
            organization: "SideSign",
            commonName: machineName
        )

        do {
            let result = try CSRBuilder.generate(subject: subject)
            self.csrData = Data(result.csrPEM.utf8)
            self.privateKey = Data(result.privateKeyPEM.utf8)
        } catch {
            debugLog("[SideSign] CertificateRequest error: Failed to generate CSR for \(machineName): \(error)")
            throw error
        }
    }
}
