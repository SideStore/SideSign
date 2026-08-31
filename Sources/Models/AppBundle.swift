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

    public var hasPrivateEntitlements: Bool = false

    public var provisioningProfile: ProvisioningProfile? {
        let url = fileURL.appendingPathComponent("embedded.mobileprovision")
        return ProvisioningProfile(fileURL: url)
    }

    public var appExtensions: Set<AppBundle> {
        loadExtensions()
    }

    public var entitlements: [String: any Sendable] {
        loadEntitlements()
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

        let infoURL = bundle.bundleURL.appendingPathComponent("Info.plist")
        guard let data = try? Data(contentsOf: infoURL),
              let info = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: any Sendable]
        else {
            return nil
        }

        guard let bundleIdentifier = (info["CFBundleIdentifier"] as? String) ?? (info["bundle-identifier"] as? String) else {
            return nil
        }

        let name = (info["CFBundleDisplayName"] as? String)
            ?? (info["CFBundleName"] as? String)
            ?? fileURL.deletingPathExtension().lastPathComponent

        let version = (info["CFBundleShortVersionString"] as? String) ?? "1.0"
        let buildVersion = (info["CFBundleVersion"] as? String) ?? "1"

        let minimumVersionString = (info["MinimumOSVersion"] as? String) ?? "1.0"
        let components = minimumVersionString.split(separator: ".")
        let minimumVersion = OperatingSystemVersion(
            majorVersion: Int(components.first ?? "1") ?? 1,
            minorVersion: components.count > 1 ? (Int(components[1]) ?? 0) : 0,
            patchVersion: components.count > 2 ? (Int(components[2]) ?? 0) : 0
        )

        func deviceType(from value: Int) -> DeviceType {
            switch value {
            case UIDeviceFamilyCodes.iPhone:     return .iPhone
            case UIDeviceFamilyCodes.iPad:       return .iPad
            case UIDeviceFamilyCodes.appleTV:    return .appleTV
            case UIDeviceFamilyCodes.appleWatch: return .appleWatch
            case UIDeviceFamilyCodes.mac:        return .mac
            case UIDeviceFamilyCodes.visionPro:  return .visionPro
            default:                             return .iPhone
            }
        }

        var supportedTypes: DeviceType = []
        if let number = info["UIDeviceFamily"] as? NSNumber {
            supportedTypes = deviceType(from: number.intValue)
        } else if let array = info["UIDeviceFamily"] as? [NSNumber] {
            for value in array {
                supportedTypes.insert(deviceType(from: value.intValue))
            }
        } else {
            supportedTypes = .iPhone
        }

        var resolvedIcon: String?
        if let icons = info["CFBundleIcons"] as? [String: any Sendable],
           let primary = icons["CFBundlePrimaryIcon"] {
            if let iconStr = primary as? String {
                resolvedIcon = iconStr
            } else if let dict = primary as? [String: any Sendable] {
                let files = dict["CFBundleIconFiles"] ?? info["CFBundleIconFiles"]
                if let files = files as? [String] {
                    resolvedIcon = files.last
                }
            }
        }

        if resolvedIcon == nil {
            resolvedIcon = info["CFBundleIconFile"] as? String
        }

        self.bundle = bundle
        self.fileURL = fileURL
        self.name = name
        self.bundleIdentifier = bundleIdentifier
        self.version = version
        self.buildVersion = buildVersion
        self.minimumiOSVersion = minimumVersion
        self.supportedDeviceTypes = supportedTypes
        self.iconName = resolvedIcon
    }

    public static func == (lhs: AppBundle, rhs: AppBundle) -> Bool {
        lhs.bundleIdentifier == rhs.bundleIdentifier && lhs.fileURL == rhs.fileURL
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(bundleIdentifier)
        hasher.combine(fileURL)
    }

    private func loadExtensions() -> Set<AppBundle> {
        let pluginsURL = fileURL.appendingPathComponent("PlugIns")
        guard let contents = try? FileManager.default.contentsOfDirectory(
            at: pluginsURL,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        ) else {
            return []
        }
        let extensions = contents
            .filter { $0.pathExtension.lowercased() == "appex" }
            .compactMap { AppBundle(fileURL: $0) }
        return Set(extensions)
    }

    private func loadEntitlements() -> [String: any Sendable] {
        let profileURL = fileURL.appendingPathComponent("embedded.mobileprovision")
        if let profileData = try? Data(contentsOf: profileURL),
           let profile = ProvisioningProfile(data: profileData) {
            return profile.entitlements
        }

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
        let executableURL = bundle.executableURL ?? fileURL.appendingPathComponent(fileURL.deletingPathExtension().lastPathComponent)
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
}
