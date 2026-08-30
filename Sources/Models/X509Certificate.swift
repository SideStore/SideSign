//
//  X509Certificate.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
import CodeSignKit

public struct X509Certificate: Sendable, Codable, Equatable, Hashable, Identifiable {
    public var id: String { serialNumber }

    public var name: String
    public var serialNumber: String
    public var identifier: String?
    public var machineName: String?
    public var machineIdentifier: String?
    public var requesterEmail: String?

    public var creationDate: Date
    public var expiryDate: Date
    public var data: Data?

    private static let pemPrefix = "-----BEGIN CERTIFICATE-----"
    private static let pemSuffix = "-----END CERTIFICATE-----"

    public init(name: String,
                serialNumber: String,
                data: Data? = nil,
                creationDate: Date = .distantPast,
                expiryDate: Date = .distantPast,
                identifier: String? = nil,
                machineName: String? = nil,
                machineIdentifier: String? = nil,
                requesterEmail: String? = nil)
    {
        self.name = name
        self.serialNumber = serialNumber
        self.data = data
        self.creationDate = creationDate
        self.expiryDate = expiryDate
        self.identifier = identifier
        self.machineName = machineName
        self.machineIdentifier = machineIdentifier
        self.requesterEmail = requesterEmail
    }

    public init?(data: Data) {
        var pemData = data

        if let prefix = String(data: data.prefix(Self.pemPrefix.count), encoding: .utf8),
           prefix != Self.pemPrefix {
            let base64 = data.base64EncodedString(options: .lineLength64Characters)
            let content = "\(Self.pemPrefix)\n\(base64)\n\(Self.pemSuffix)"
            pemData = content.data(using: .utf8)!
        }

        guard let parsed = CertificateParser.parseCertificate(pemData) else { return nil }

        var serial = parsed.serial
        if let idx = serial.firstIndex(where: { $0 != "0" }) {
            serial = String(serial[idx...])
        } else if serial.isEmpty {
            return nil
        }

        self.init(
            name: parsed.name,
            serialNumber: serial,
            data: pemData,
            creationDate: parsed.creationDate ?? .distantPast,
            expiryDate: parsed.expiryDate ?? .distantPast
        )
    }
}
