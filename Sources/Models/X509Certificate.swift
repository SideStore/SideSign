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
        case requesterFirstName
        case requesterLastName
        case displayName
        case certificateType
        case certificateTypeName
        case certificateTypeId
        case platform
        case platformName
        case isManaged
        case status
        case ownerName
        case ownerId
        case autoRotationEnabled
        case requestedDate
        case serialNumDecimal
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
    var requesterFirstName: String? {
        get { self[.requesterFirstName] }
        set { self[.requesterFirstName] = newValue }
    }
    var requesterLastName: String? {
        get { self[.requesterLastName] }
        set { self[.requesterLastName] = newValue }
    }
    var displayName: String? {
        get { self[.displayName] }
        set { self[.displayName] = newValue }
    }
    var certificateType: String? {
        get { self[.certificateType] }
        set { self[.certificateType] = newValue }
    }
    var certificateTypeName: String? {
        get { self[.certificateTypeName] }
        set { self[.certificateTypeName] = newValue }
    }
    var certificateTypeId: String? {
        get { self[.certificateTypeId] }
        set { self[.certificateTypeId] = newValue }
    }
    var platform: String? {
        get { self[.platform] }
        set { self[.platform] = newValue }
    }
    var platformName: String? {
        get { self[.platformName] }
        set { self[.platformName] = newValue }
    }
    var isManaged: Bool? {
        get { self[.isManaged].flatMap { Bool($0) } }
        set { self[.isManaged] = newValue.map { String($0) } }
    }
    var status: String? {
        get { self[.status] }
        set { self[.status] = newValue }
    }
    var ownerName: String? {
        get { self[.ownerName] }
        set { self[.ownerName] = newValue }
    }
    var ownerId: String? {
        get { self[.ownerId] }
        set { self[.ownerId] = newValue }
    }
    var autoRotationEnabled: Bool? {
        get { self[.autoRotationEnabled].flatMap { Bool($0) } }
        set { self[.autoRotationEnabled] = newValue.map { String($0) } }
    }
    var requestedDate: String? {
        get { self[.requestedDate] }
        set { self[.requestedDate] = newValue }
    }
    var serialNumDecimal: String? {
        get { self[.serialNumDecimal] }
        set { self[.serialNumDecimal] = newValue }
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
        requesterFirstName: String? = nil,
        requesterLastName: String? = nil,
        displayName: String? = nil,
        certificateType: String? = nil,
        certificateTypeName: String? = nil,
        certificateTypeId: String? = nil,
        platform: String? = nil,
        platformName: String? = nil,
        isManaged: Bool? = nil,
        status: String? = nil,
        ownerName: String? = nil,
        ownerId: String? = nil,
        autoRotationEnabled: Bool? = nil,
        requestedDate: String? = nil,
        serialNumDecimal: String? = nil,
        sourceEndpoint: CertificateEndpoint? = nil
    ) {
        self.init(data: data)
        if let identifier { self.identifier = identifier }
        if let machineName { self.machineName = machineName }
        if let machineIdentifier { self.machineIdentifier = machineIdentifier }
        if let requesterEmail { self.requesterEmail = requesterEmail }
        if let requesterFirstName { self.requesterFirstName = requesterFirstName }
        if let requesterLastName { self.requesterLastName = requesterLastName }
        if let displayName { self.displayName = displayName }
        if let certificateType { self.certificateType = certificateType }
        if let certificateTypeName { self.certificateTypeName = certificateTypeName }
        if let certificateTypeId { self.certificateTypeId = certificateTypeId }
        if let platform { self.platform = platform }
        if let platformName { self.platformName = platformName }
        if let isManaged { self.isManaged = isManaged }
        if let status { self.status = status }
        if let ownerName { self.ownerName = ownerName }
        if let ownerId { self.ownerId = ownerId }
        if let autoRotationEnabled { self.autoRotationEnabled = autoRotationEnabled }
        if let requestedDate { self.requestedDate = requestedDate }
        if let serialNumDecimal { self.serialNumDecimal = serialNumDecimal }
        if let sourceEndpoint { self.sourceEndpoint = sourceEndpoint }
    }
}
