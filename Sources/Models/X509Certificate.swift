//
//  X509Certificate.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
import CodeSignKit

public extension X509Certificate {
    enum MetadataKey: String, Sendable, CaseIterable {
        case identifier
        case machineName
        case machineIdentifier
        case requesterEmail
    }

    subscript(key: MetadataKey) -> String? {
        get { metadata[key.rawValue] }
        set { metadata[key.rawValue] = newValue }
    }

    var identifier: String? {
        get { self[.identifier] }
        set { self[.identifier] = newValue }
    }
    var machineName: String? {
        get { self[.machineName] }
        set { self[.machineName] = newValue }
    }
    var machineIdentifier: String? {
        get { self[.machineIdentifier] }
        set { self[.machineIdentifier] = newValue }
    }
    var requesterEmail: String? {
        get { self[.requesterEmail] }
        set { self[.requesterEmail] = newValue }
    }

    var name: String { commonName ?? subjectSummary }
    var serialNumber: String { serialNumberHex }
    var data: Data? { rawDER }
    var creationDate: Date { notBefore ?? .distantPast }
    var expiryDate: Date { notAfter ?? .distantPast }
    var x509: X509Certificate { self }

    private static let pemPrefix = "-----BEGIN CERTIFICATE-----"
    private static let pemSuffix = "-----END CERTIFICATE-----"

    init?(data: Data, metadata: [String: String] = [:]) {
        var pemData = data

        if let prefix = String(data: data.prefix(Self.pemPrefix.count), encoding: .utf8),
           prefix != Self.pemPrefix {
            let base64 = data.base64EncodedString(options: .lineLength64Characters)
            let content = "\(Self.pemPrefix)\n\(base64)\n\(Self.pemSuffix)"
            pemData = content.data(using: .utf8)!
        }

        guard let der = CertificateParser.extractDER(pemData) else { return nil }
        self.init(der: der, metadata: metadata)
    }

    init?(
        data: Data,
        identifier: String? = nil,
        machineName: String? = nil,
        machineIdentifier: String? = nil,
        requesterEmail: String? = nil
    ) {
        self.init(data: data)
        if let identifier { self.identifier = identifier }
        if let machineName { self.machineName = machineName }
        if let machineIdentifier { self.machineIdentifier = machineIdentifier }
        if let requesterEmail { self.requesterEmail = requesterEmail }
    }

    init(
        name: String,
        serialNumber: String,
        data: Data? = nil,
        creationDate: Date = .distantPast,
        expiryDate: Date = .distantPast,
        identifier: String? = nil,
        machineName: String? = nil,
        machineIdentifier: String? = nil,
        requesterEmail: String? = nil
    ) {
        if let data, let cert = X509Certificate(data: data, identifier: identifier, machineName: machineName, machineIdentifier: machineIdentifier, requesterEmail: requesterEmail) {
            self = cert
        } else {
            var cert = X509Certificate(der: data ?? Data([0x30, 0x06, 0x30, 0x04, 0x02, 0x01, 0x00, 0x00])) ?? X509Certificate(der: Data())!
            if let identifier { cert.identifier = identifier }
            if let machineName { cert.machineName = machineName }
            if let machineIdentifier { cert.machineIdentifier = machineIdentifier }
            if let requesterEmail { cert.requesterEmail = requesterEmail }
            self = cert
        }
    }
}
