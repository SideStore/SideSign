//
//  KeyStore.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
import CodeSignKit

public struct KeyStore: Sendable, Equatable, Hashable, Identifiable {
    public var id: String { certificate.serialNumber }

    public var certificate: X509Certificate
    public var privateKey: Data
    public var password: String?

    public init(
        certificate: X509Certificate,
        privateKey: Data,
        password: String? = nil
    ) {
        self.certificate = certificate
        self.privateKey = privateKey
        self.password = password
    }

    public init(p12Data: Data, password: String) throws {
        let result = try PKCS12Parser.extract(p12Data, password: password)

        guard let x509 = X509Certificate(data: result.cert) else {
            debugLog("[SideSign] KeyStore error: Failed to parse certificate from PKCS#12 payload")
            throw CertificateError.invalidData(cause: "Failed to parse certificate from PKCS#12 payload")
        }

        self.certificate = x509
        self.privateKey = result.key
        self.password = password
    }

    public func exportP12(password: String? = nil) throws -> Data {
        guard let certData = certificate.data else {
            debugLog("[SideSign] KeyStore error: Certificate PEM data is missing")
            throw CertificateError.invalidData(cause: "Certificate PEM data is missing")
        }
        return try PKCS12Parser.create(
            cert: certData,
            key: privateKey,
            password: password
        )
    }
}
