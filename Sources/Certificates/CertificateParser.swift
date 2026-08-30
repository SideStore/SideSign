//
//  CertificateParser.swift
//  SideSign
//
//  Created by Magesh K on 07/07/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
import CodeSignKit

public enum CertificateParser {
    public static func extractDER(_ data: Data, boundaryKeyword: String = "CERTIFICATE") -> Data? {
        if let str = String(data: data, encoding: .utf8), str.contains("-----BEGIN ") {
            return ASN1Helper.decodePEM(str)
        }
        return data
    }

    public static func extractX509(_ data: Data) -> X509Certificate? {
        guard let der = extractDER(data) else { return nil }
        return X509Certificate(der: der)
    }

    public static func parseCertificate(_ data: Data) -> (name: String, serial: String, creationDate: Date?, expiryDate: Date?)? {
        guard let cert = extractX509(data) else { return nil }
        return (cert.commonName ?? cert.subjectSummary, cert.serialNumberHex, cert.notBefore, cert.notAfter)
    }
}
