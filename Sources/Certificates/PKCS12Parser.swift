//
//  PKCS12Parser.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
import CodeSignKit

public enum PKCS12Parser {
    public static func extract(_ data: Data, password: String?) throws -> (cert: Data, key: Data) {
        do {
            let parser = try CodeSignKit.PKCS12Parser(p12Data: data, password: password ?? "")
            guard let certDER = parser.leafCertificate?.rawDER else {
                throw CertificateError.pkcs12ImportFailed(cause: "No X.509 certificate in PKCS#12 archive")
            }
            return (certDER, parser.privateKeyDER ?? Data())
        } catch {
            throw CertificateError.pkcs12ImportFailed(cause: error.localizedDescription)
        }
    }

    public static func create(cert: Data, key: Data?, password: String?) throws -> Data {
        guard let certDER = CertificateParser.extractDER(cert) else {
            throw CertificateError.invalidData(cause: "Invalid certificate data")
        }
        let keyDER = key.flatMap { CertificateParser.extractDER($0, boundaryKeyword: "PRIVATE KEY") } ?? key
        do {
            return try PKCS12Builder.build(certificateDER: certDER, privateKeyDER: keyDER, password: password)
        } catch {
            throw CertificateError.pkcs12ExportFailed(cause: error.localizedDescription)
        }
    }

    public static func extractUnencrypted(_ data: Data) throws -> (cert: Data, key: Data) {
        try extract(data, password: nil)
    }

    public static func createUnencrypted(cert: Data, key: Data?) throws -> Data {
        try create(cert: cert, key: key, password: nil)
    }
}
