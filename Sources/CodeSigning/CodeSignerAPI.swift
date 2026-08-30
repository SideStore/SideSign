//
//  CodeSignerAPI.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
import CodeSignKit

public protocol CodeSignerAPI: Sendable {
    var team: Team { get }
    var keyStore: KeyStore { get }

    func signApp(at appURL: URL, provisioningProfiles profiles: [ProvisioningProfile], progress: Progress?) async throws
}

public extension CodeSignerAPI {
    func signApp(at appURL: URL, provisioningProfiles profiles: [ProvisioningProfile]) async throws {
        try await signApp(at: appURL, provisioningProfiles: profiles, progress: nil)
    }
}

public struct AppBundleSigner: CodeSignerAPI, Sendable {
    public let team: Team
    public let keyStore: KeyStore

    private enum SigningTargetType: CustomStringConvertible {
        case mainAppBundleDirectory
        case mainAppExecutable
        case appExtensionBundle(identifier: String)
        case appExtensionExecutable(identifier: String)
        case framework
        case dylib
        case unmatched

        var description: String {
            switch self {
            case .mainAppBundleDirectory:
                return ".mainAppBundleDirectory"
            case .mainAppExecutable:
                return ".mainAppExecutable"
            case .appExtensionBundle(let id):
                return ".appExtensionBundle('\(id)')"
            case .appExtensionExecutable(let id):
                return ".appExtensionExecutable('\(id)')"
            case .framework:
                return ".framework"
            case .dylib:
                return ".dylib"
            case .unmatched:
                return ".unmatched"
            }
        }
    }

    public init(team: Team, keyStore: KeyStore) {
        self.team = team
        self.keyStore = keyStore
    }

    public func signApp(at appURL: URL, provisioningProfiles profiles: [ProvisioningProfile], progress: Progress? = nil) async throws
    {
        debugLog("[SideSign] AppBundleSigner.signApp called")
        verboseLog("[SideSign] URL: \(appURL.path), Profiles: \(profiles.map { "\($0.name) (\($0.bundleIdentifier))" })")

        guard let appBundle = AppBundle(fileURL: appURL) else {
            debugLog("[SideSign] AppBundleSigner.signApp error: Failed to parse AppBundle")
            verboseLog("[SideSign] Path: \(appURL.path)")
            throw SignerError.invalidApp(cause: "Failed to parse AppBundle at \(appURL.path)")
        }

        debugLog("[SideSign] AppBundleSigner.signApp started")
        verboseLog("[SideSign] BundleID: \(appBundle.bundleIdentifier)")

        func profile(for app: AppBundle) -> ProvisioningProfile? {
            for p in profiles where p.bundleIdentifier == app.bundleIdentifier {
                return p
            }
            return profiles.first
        }

        var entitlementsByURL: [URL: String] = [:]

        func prepare(_ app: AppBundle) throws {
            verboseLog("[SideSign] AppBundleSigner.prepare started for: \(app.bundleIdentifier)")

            guard let matchedProfile = profile(for: app) else {
                debugLog("[SideSign] AppBundleSigner.prepare error: Missing provisioning profile")
                verboseLog("[SideSign] BundleID: \(app.bundleIdentifier)")
                throw SignerError.missingProvisioningProfile(bundleIdentifier: app.bundleIdentifier)
            }

            let profileURL = app.fileURL.appendingPathComponent("embedded.mobileprovision")
            verboseLog("[SideSign] Writing mobileprovision to: \(profileURL.path)")
            try matchedProfile.data.write(to: profileURL)

            var filteredEntitlements = matchedProfile.entitlements
            verboseLog("[SideSign] Original profile entitlements: \(filteredEntitlements)")

            let applicationEntitlements = app.entitlements

            for (key, _) in filteredEntitlements {
                if let applicationValue = applicationEntitlements[key] {
                    if key == "keychain-access-groups" {
                        guard let groups = applicationValue as? [String] else {
                            verboseLog("[SideSign] The app's keychain-access-groups entitlement is not an array of strings.")
                            continue
                        }

                        filteredEntitlements[key] = try groups.map { group in
                            guard let separator = group.firstIndex(of: ".") else {
                                debugLog("[SideSign] The keychain access group does not contain a Team ID prefix")
                                verboseLog("[SideSign] Group: '\(group)'")
                                throw SignerError.invalidApp(cause: "The keychain access group '\(group)' does not contain a Team ID prefix.")
                            }
                            return matchedProfile.teamIdentifier + group[separator...]
                        }
                    }
                } else if key != "application-identifier"               &&
                          key != "com.apple.developer.team-identifier"  &&
                          key != "get-task-allow" 
                {
                    filteredEntitlements.removeValue(forKey: key)
                }
            }

            verboseLog("[SideSign] Filtered entitlements for signing: \(filteredEntitlements)")

            let plist = try PropertyListSerialization.data(
                fromPropertyList: filteredEntitlements,
                format: .xml,
                options: 0
            )

            guard let string = String(data: plist, encoding: .utf8) else {
                debugLog("[SideSign] AppBundleSigner.prepare error: Failed to convert plist data to XML string")
                throw SignerError.unknown(cause: "Failed to convert plist data to XML string")
            }

            verboseLog("[SideSign] Prepared Entitlements XML for \(app.bundleIdentifier):\n\(string)")
            entitlementsByURL[app.fileURL.resolvingSymlinksInPath()] = string
        }

        do {
            try prepare(appBundle)

            for ext in appBundle.appExtensions {
                verboseLog("[SideSign] Found app extension: \(ext.bundleIdentifier) at \(ext.fileURL.path)")
                try prepare(ext)
            }

            let keyData = try keyStore.exportP12()

            verboseLog("[SideSign] Invoking CodeSigner.sign for appPath: \(appBundle.fileURL.path)")
            try CodeSigner.sign(
                appPath: appBundle.fileURL.path,
                keyData: keyData,
                entitlementProvider: { path in
                    let normPath = path.trimmingCharacters(in: .whitespacesAndNewlines)
                    let appResolved = appBundle.fileURL.resolvingSymlinksInPath()

                    let targetType: SigningTargetType
                    let xml: String

                    if normPath.isEmpty {
                        targetType = .mainAppBundleDirectory
                        xml = entitlementsByURL[appResolved] ?? ""
                    } else {
                        let url: URL = normPath.hasPrefix("/") ? URL(fileURLWithPath: normPath) : appBundle.fileURL.appendingPathComponent(normPath)
                        let resolved = url.resolvingSymlinksInPath()

                        if resolved == appResolved {
                            targetType = .mainAppBundleDirectory
                            xml = entitlementsByURL[appResolved] ?? ""
                        } else if let matchedExt = appBundle.appExtensions.first(where: { ext in
                            let extResolved = ext.fileURL.resolvingSymlinksInPath()
                            return resolved == extResolved ||
                                   resolved.path.hasPrefix(extResolved.path + "/") ||
                                   resolved.lastPathComponent == extResolved.lastPathComponent ||
                                   resolved.deletingPathExtension().lastPathComponent == extResolved.deletingPathExtension().lastPathComponent
                        }) {
                            let extResolved = matchedExt.fileURL.resolvingSymlinksInPath()
                            if resolved == extResolved {
                                targetType = .appExtensionBundle(identifier: matchedExt.bundleIdentifier)
                            } else {
                                targetType = .appExtensionExecutable(identifier: matchedExt.bundleIdentifier)
                            }
                            xml = entitlementsByURL[extResolved] ?? ""
                        } else if resolved.pathExtension.lowercased() == "framework" || resolved.path.contains(".framework") {
                            targetType = .framework
                            xml = ""
                        } else if resolved.pathExtension.lowercased() == "dylib" || resolved.lastPathComponent.hasSuffix(".dylib") {
                            targetType = .dylib
                            xml = ""
                        } else if resolved.deletingLastPathComponent() == appResolved ||
                                  resolved.path.hasPrefix(appResolved.path + "/") {
                            targetType = .mainAppExecutable
                            xml = entitlementsByURL[appResolved] ?? ""
                        } else {
                            targetType = .unmatched
                            xml = ""
                        }
                    }

                    let xmlStatus = xml.isEmpty ? "none" : "present (\(xml.count) bytes)"
                    verboseLog("[SideSign] AppBundleSigner entitlementProvider queried path: '\(path)' [Type: \(targetType)], xml: \(xmlStatus)")
                    return xml
                },
                progress: {
                    progress?.completedUnitCount += 1
                }
            )

            debugLog("[SideSign] AppBundleSigner.signApp completed successfully")
            verboseLog("[SideSign] App URL: \(appURL.path)")
        } catch {
            debugLog("[SideSign] AppBundleSigner.signApp failed with error: \(error)")
            throw error
        }
    }
}
