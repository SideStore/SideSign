//
//  AppBundle.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
import CodeSignKit

public struct AppBundle: Sendable, Identifiable, Hashable, Equatable {
    public var id: String { bundleIdentifier }

    public let name: String
    public let bundleIdentifier: String
    public let version: String
    public let buildVersion: String
    public let minimumiOSVersion: OperatingSystemVersion
    public let supportedDeviceTypes: DeviceType
    public let fileURL: URL
    public let bundle: Bundle
    public let iconName: String?
    public let provisioningProfile: ProvisioningProfile?
    public let infoPlist: [String: any Sendable]

    public var hasPrivateEntitlements: Bool = false

    public var profileEntitlements: [String: any Sendable]? {
        provisioningProfile?.entitlements
    }

    public var appExtensions: Set<AppBundle> {
        loadExtensions()
    }

    public var isExtension: Bool {
        fileURL.pathExtension.lowercased() == "appex"
    }

    public var entitlements: [String: any Sendable] {
        loadEntitlements()
    }

    public var infoPlistURL: URL {
        InfoPlistParser.resolveInfoPlistURL(for: fileURL)
    }

    public var executableURL: URL? {
        bundle.executableURL
    }

    public var executableName: String? {
        bundle.executableURL?.lastPathComponent
    }

    public var entitlementsString: String {
        loadEntitlementsString()
    }

    public var iconURL: URL? {
        guard let iconName else { return nil }

        let candidates = [
            fileURL.appendingPathComponent("\(iconName)@3x.png"),
            fileURL.appendingPathComponent("\(iconName)@2x.png"),
            fileURL.appendingPathComponent("\(iconName).png"),
            fileURL.appendingPathComponent(iconName)
        ]

        return candidates.first { FileManager.default.fileExists(atPath: $0.path) }
    }

    public init?(fileURL: URL) {
        guard let bundle = Bundle(url: fileURL) else {
            return nil
        }

        guard let parser = try? InfoPlistParser(bundleURL: fileURL),
              let bundleIdentifier = parser.bundleIdentifier
        else {
            return nil
        }

        let name = parser.displayName
            ?? parser.bundleName
            ?? fileURL.deletingPathExtension().lastPathComponent

        let version = parser.shortVersionString ?? "1.0"
        let buildVersion = parser.buildVersion ?? "1"
        let minimumVersion = parser.operatingSystemVersion
        let supportedTypes = parser.supportedDeviceTypes
        let resolvedIcon = parser.primaryIconName

        let profileURL = fileURL.appendingPathComponent("embedded.mobileprovision")
        self.provisioningProfile = try? ProvisioningProfile(fileURL: profileURL)

        self.bundle = bundle
        self.fileURL = fileURL
        self.name = name
        self.bundleIdentifier = bundleIdentifier
        self.version = version
        self.buildVersion = buildVersion
        self.minimumiOSVersion = minimumVersion
        self.supportedDeviceTypes = supportedTypes
        self.iconName = resolvedIcon
        self.infoPlist = parser.rawDictionary
    }

    public static func == (lhs: AppBundle, rhs: AppBundle) -> Bool {
        lhs.bundleIdentifier == rhs.bundleIdentifier && lhs.fileURL == rhs.fileURL
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(bundleIdentifier)
        hasher.combine(fileURL)
    }

    private func loadExtensions() -> Set<AppBundle> {
        // App extensions live in PlugIns/; ExtensionKit extensions (EXAppExtensionAttributes,
        // e.g. PhotoKit background upload) live in Extensions/.
        let contents = ["PlugIns", "Extensions"].flatMap { folder in
            (try? FileManager.default.contentsOfDirectory(
                at: fileURL.appendingPathComponent(folder),
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            )) ?? []
        }
        let extensions = contents
            .filter { $0.pathExtension.lowercased() == "appex" }
            .compactMap { AppBundle(fileURL: $0) }
        return Set(extensions)
    }

    private func loadEntitlements() -> [String: any Sendable] {
        if !entitlementsString.isEmpty,
           let data = entitlementsString.data(using: .utf8),
           let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: any Sendable] {
            return plist
        }

        return [:]
    }

    private func loadEntitlementsString() -> String {
        (try? MachOParser.entitlements(at: fileURL)) ?? ""
    }
}

public extension AppBundle {

    func dumpMachOInfo() -> String {
        guard let executableURL = self.executableURL else {
            return "[SideSign] Executable binary not found for \(fileURL.lastPathComponent)"
        }
        guard let parser = try? MachOParser(url: executableURL) else {
            return "[SideSign] MachOParser failed to load \(executableURL.lastPathComponent)"
        }

        var info = "--- Mach-O Binary Info: \(executableURL.lastPathComponent) ---\n"
        info += "Path: \(fileURL.path)\n"
        info += "Architectures: \(parser.architectures().joined(separator: ", "))\n"
        if let platform = parser.platformType() {
            info += "Platform: \(platform)\n"
        }
        if let minOS = parser.minimumOSVersion() {
            info += "Min OS Version: \(minOS)\n"
        }
        info += "Encrypted (DRM): \(parser.isEncrypted() ? "Yes" : "No")\n"
        if let teamID = parser.teamID() {
            info += "Team ID: \(teamID)\n"
        }

        let certs = parser.certificates()
        if !certs.isEmpty {
            info += "Certificates (\(certs.count)):\n"
            for (index, cert) in certs.enumerated() {
                let subject = X509Certificate(data: cert)?.name ?? "Certificate \(index + 1) (\(cert.count) bytes)"
                info += "  [\(index)] \(subject)\n"
            }
        }

        let libs = parser.linkedLibraries()
        if !libs.isEmpty {
            info += "Linked Libraries (\(libs.count)):\n"
            for lib in libs {
                info += "  - \(lib)\n"
            }
        }

        let segs = parser.segments()
        if !segs.isEmpty {
            info += "Segments (\(segs.count)):\n"
            for seg in segs {
                info += "  - \(seg.name) (offset: \(seg.offset), size: \(seg.size))\n"
            }
        }

        info += "----------------------------------------"
        return info
    }

    func writeInfoPlist(_ plist: [String: any Sendable]) throws {
        try InfoPlistParser(dictionary: plist).write(to: infoPlistURL)
    }

    func updateInfoPlist(with plist: [String: any Sendable], deep: Bool = true) throws {
        var parser = try InfoPlistParser(plistURL: infoPlistURL)
        parser.merge(plist, deep: deep)
        try parser.write(to: infoPlistURL)
    }

    var allEntitlements: [String: [String: any Sendable]] {
        var map: [String: [String: any Sendable]] = [bundleIdentifier: entitlements]
        for ext in appExtensions {
            map[ext.bundleIdentifier] = ext.entitlements
        }
        return map
    }

    var allAppBundles: [AppBundle] {
        [self] + Array(appExtensions).sorted { $0.bundleIdentifier.localizedCaseInsensitiveCompare($1.bundleIdentifier) == .orderedAscending }
    }

    func appExtension(withBundleIdentifier id: String) -> AppBundle? {
        appExtensions.first { $0.bundleIdentifier == id }
    }

    func appBundle(withBundleIdentifier id: String) -> AppBundle? {
        if bundleIdentifier == id {
            return self
        }
        return appExtension(withBundleIdentifier: id)
    }

    func entitlements(for bundleIdentifier: String) -> [String: any Sendable]? {
        allEntitlements[bundleIdentifier]
    }
}
