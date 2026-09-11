//
//  X509Certificate.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
@_exported import struct CodeSignKit.X509Certificate

public extension X509Certificate {
    enum MetadataKey: String, Sendable, CaseIterable {
        case identifier
        case machineName
        case machineIdentifier
        case requesterEmail
        case certificateType
        case platform
        case sourceEndpoint
    }

    public enum CertificateEndpoint: String, Sendable, Codable, CaseIterable {
        case developerServices2
        case developerPortal

        public var url: URL {
            switch self {
            case .developerServices2:
                return Constants.URLs.certificatesDeveloperServices2
            case .developerPortal:
                return Constants.URLs.certificatesDeveloperPortal
            }
        }
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
    var certificateType: String? {
        get { self[.certificateType] }
        set { self[.certificateType] = newValue }
    }
    var platform: String? {
        get { self[.platform] }
        set { self[.platform] = newValue }
    }
    var sourceEndpoint: CertificateEndpoint? {
        get { self[.sourceEndpoint].flatMap { CertificateEndpoint(rawValue: $0) } }
        set { self[.sourceEndpoint] = newValue?.rawValue }
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
        requesterEmail: String? = nil,
        certificateType: String? = nil,
        platform: String? = nil,
        sourceEndpoint: CertificateEndpoint? = nil
    ) {
        self.init(data: data)
        if let identifier { self.identifier = identifier }
        if let machineName { self.machineName = machineName }
        if let machineIdentifier { self.machineIdentifier = machineIdentifier }
        if let requesterEmail { self.requesterEmail = requesterEmail }
        if let certificateType { self.certificateType = certificateType }
        if let platform { self.platform = platform }
        if let sourceEndpoint { self.sourceEndpoint = sourceEndpoint }
    }
}
