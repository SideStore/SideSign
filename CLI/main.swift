//
//  main.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideStore. All rights reserved.
//

import Foundation
import SideSign
import CodeSignKit
import GSACryptoKit

func printUsage() {
    print("""
    sidesign - Advanced App Signing, CodeSignKit, and Apple Developer Portal CLI for iOS, macOS, tvOS, visionOS, watchOS

    Usage:
      sidesign <command> [options]

    Commands:
      sign                  Sign an IPA, .app bundle, framework, dylib, or Mach-O binary
      verify                Verify code signatures and integrity
      display / inspect     Inspect signatures, entitlements, Mach-O slices, or bundle metadata
      profile               Inspect, dump, or validate .mobileprovision profiles
      extensions            List or remove App Extensions from an IPA or .app bundle
      archive               Unzip IPAs to .app bundles or repackage .app bundles to IPAs
      auth                  Apple ID authentication, 2FA, and Developer Portal operations
      anisette              Generate Anisette headers from remote or local providers
      remove-signature      Remove code signature from Mach-O binary or bundle

    Global Options:
      --verbose, -v         Enable verbose logging
      --debug, -d           Enable debug logging
      --help, -h            Show help and usage information

    Examples:
      # Sign an IPA with P12 and Mobileprovision:
      sidesign sign app.ipa --p12 dev.p12 --password secret --profile dev.mobileprovision --output signed.ipa

      # Inspect an App Bundle:
      sidesign inspect app.ipa --entitlements

      # Dump Provisioning Profile info:
      sidesign profile dump embedded.mobileprovision

      # Remove extensions from an IPA to stay within active app limits:
      sidesign extensions remove app.ipa --all --output app_no_ext.ipa

      # Apple Developer Portal login & 2FA:
      sidesign auth login --apple-id developer@example.com

      # Register a new device UDID:
      sidesign auth devices register --name "My iPhone" --udid <DEVICE_UDID> --apple-id developer@example.com
    """)
}

func handleSign(args: [String]) async throws {
    var targetPath: String?
    var p12Path: String?
    var password = ""
    var profilePath: String?
    var bundleID: String?
    var teamID: String?
    var entitlementsPath: String?
    var outputPath: String?
    var isDeep = true
    var isForce = true

    var i = 0
    while i < args.count {
        let arg = args[i]
        if arg == "--p12" || arg == "-p" {
            if i + 1 < args.count { p12Path = args[i + 1]; i += 1 }
        } else if arg == "--password" || arg == "-pwd" {
            if i + 1 < args.count { password = args[i + 1]; i += 1 }
        } else if arg == "--profile" || arg == "-m" {
            if i + 1 < args.count { profilePath = args[i + 1]; i += 1 }
        } else if arg == "--bundle-id" || arg == "-i" || arg == "--id" {
            if i + 1 < args.count { bundleID = args[i + 1]; i += 1 }
        } else if arg == "--team" || arg == "--team-id" {
            if i + 1 < args.count { teamID = args[i + 1]; i += 1 }
        } else if arg == "--entitlements" || arg == "-e" {
            if i + 1 < args.count { entitlementsPath = args[i + 1]; i += 1 }
        } else if arg == "--output" || arg == "-o" {
            if i + 1 < args.count { outputPath = args[i + 1]; i += 1 }
        } else if arg == "--deep" {
            isDeep = true
        } else if arg == "--force" || arg == "-f" {
            isForce = true
        } else if !arg.hasPrefix("-") && targetPath == nil {
            targetPath = arg
        }
        i += 1
    }

    guard let target = targetPath else {
        print("Error: No target IPA, .app, or binary specified.")
        exit(1)
    }

    let targetURL = URL(fileURLWithPath: target)
    var isDir: ObjCBool = false
    guard FileManager.default.fileExists(atPath: targetURL.path, isDirectory: &isDir) else {
        print("Error: Target path does not exist: \(target)")
        exit(1)
    }

    guard let p12 = p12Path else {
        print("Error: P12 certificate is required for signing (--p12 <path>).")
        exit(1)
    }

    let p12URL = URL(fileURLWithPath: p12)
    guard FileManager.default.fileExists(atPath: p12URL.path) else {
        print("Error: P12 file does not exist: \(p12)")
        exit(1)
    }

    let p12Data = try Data(contentsOf: p12URL)
    let keyStore = try KeyStore(p12Data: p12Data, password: password)

    let isIPA = targetURL.pathExtension.lowercased() == "ipa"
    let isApp = targetURL.pathExtension.lowercased() == "app"

    if isIPA || isApp {
        let workingDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: workingDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: workingDir) }

        let appURL: URL
        if isIPA {
            print("[Unpack] Unpacking IPA...")
            appURL = try FileManager.default.unzipAppBundle(at: targetURL, to: workingDir)
        } else {
            appURL = targetURL
        }

        var profiles: [ProvisioningProfile] = []
        if let profilePath = profilePath {
            let profURL = URL(fileURLWithPath: profilePath)
            let profData = try Data(contentsOf: profURL)
            let profile = try ProvisioningProfile(data: profData)
            profiles.append(profile)
        }

        let effectiveTeamID = teamID ?? profiles.first?.teamIdentifier ?? keyStore.certificate.teamIdentifier ?? "UNKNOWN"
        let team = Team(name: keyStore.certificate.organization ?? "Developer", identifier: effectiveTeamID, type: .free)

        print("[Sign] Signing App Bundle: \(appURL.lastPathComponent)")
        let signer = AppBundleSigner(team: team, keyStore: keyStore)
        try await signer.signApp(at: appURL, provisioningProfiles: profiles)

        if isIPA {
            print("[Package] Repackaging IPA...")
            let finalOutURL: URL
            if let outputPath = outputPath {
                finalOutURL = URL(fileURLWithPath: outputPath)
            } else {
                let outName = targetURL.deletingPathExtension().lastPathComponent + "_signed.ipa"
                finalOutURL = targetURL.deletingLastPathComponent().appendingPathComponent(outName)
            }
            let zippedIPA = try FileManager.default.zipAppBundle(at: appURL, compressionLevel: .fastest)
            if FileManager.default.fileExists(atPath: finalOutURL.path) {
                try FileManager.default.removeItem(at: finalOutURL)
            }
            try FileManager.default.moveItem(at: zippedIPA, to: finalOutURL)
            print("Successfully signed IPA: \(finalOutURL.path)")
        } else {
            if let outputPath = outputPath {
                let finalAppURL = URL(fileURLWithPath: outputPath)
                if FileManager.default.fileExists(atPath: finalAppURL.path) {
                    try FileManager.default.removeItem(at: finalAppURL)
                }
                try FileManager.default.copyItem(at: appURL, to: finalAppURL)
                print("Successfully signed App Bundle: \(finalAppURL.path)")
            } else {
                print("Successfully signed App Bundle in place: \(appURL.path)")
            }
        }
    } else {
        print("[Sign] Signing Mach-O / Binary with CodeSignKit: \(targetURL.lastPathComponent)")
        var entitlementsXML: String? = nil
        if let entPath = entitlementsPath {
            entitlementsXML = try String(contentsOfFile: entPath, encoding: .utf8)
        }

        if isDir.boolValue {
            try CodeSignKit.CodeSigner.sign(
                appPath: targetURL.path,
                keyData: p12Data,
                password: password,
                teamID: teamID,
                entitlementProvider: { _ in entitlementsXML ?? "" },
                progress: {}
            )
            print("\(target): signed bundle successfully")
        } else {
            let binaryData = try Data(contentsOf: targetURL)
            let cmsSigner = CMSSigner(p12Data: p12Data, password: password)
            let finalBundleID = bundleID ?? targetURL.lastPathComponent

            let signer = MachOSigner(
                binaryData: binaryData,
                bundleIdentifier: finalBundleID,
                teamIdentifier: teamID,
                entitlementsXML: entitlementsXML,
                infoPlistData: nil,
                codeResourcesData: nil,
                cmsSigner: cmsSigner,
                isMainExecutable: true
            )
            let signed = try signer.sign()
            try signed.write(to: targetURL, options: .atomic)
            print("\(target): signed Mach-O binary successfully")
        }
    }
}

func handleVerify(args: [String]) throws {
    var targetPath: String?
    var isDeep = false
    var isStrict = false

    for arg in args {
        if arg == "--deep" {
            isDeep = true
        } else if arg == "--strict" {
            isStrict = true
        } else if !arg.hasPrefix("-") && targetPath == nil {
            targetPath = arg
        }
    }

    guard let target = targetPath else {
        print("Error: No target specified for verification.")
        exit(1)
    }

    let targetURL = URL(fileURLWithPath: target)
    print("[Verify] Verifying signature for: \(targetURL.path)")
    let result = CodeSignKit.SignatureVerifier.verify(url: targetURL, deep: isDeep, strict: isStrict)
    if result.isValid {
        print("Signature is VALID.")
        if let ident = result.bundleIdentifier { print("Identifier=\(ident)") }
        if let team = result.teamIdentifier { print("TeamIdentifier=\(team)") }
        if let cdHash = result.cdHash { print("CDHash=\(cdHash)") }
    } else {
        print("Signature is INVALID.")
        for err in result.errors {
            print("  - \(err)")
        }
        exit(1)
    }
}

func handleDisplay(args: [String]) throws {
    var targetPath: String?
    var dumpEntitlements = false
    var dumpRequirements = false

    for arg in args {
        if arg == "--entitlements" || arg == "-e" {
            dumpEntitlements = true
        } else if arg == "--requirements" || arg == "-r" {
            dumpRequirements = true
        } else if !arg.hasPrefix("-") && targetPath == nil {
            targetPath = arg
        }
    }

    guard let target = targetPath else {
        print("Error: No target specified for display/inspection.")
        exit(1)
    }

    let targetURL = URL(fileURLWithPath: target)
    var isDir: ObjCBool = false
    _ = FileManager.default.fileExists(atPath: targetURL.path, isDirectory: &isDir)

    let isIPA = targetURL.pathExtension.lowercased() == "ipa"
    let isApp = targetURL.pathExtension.lowercased() == "app"

    if isIPA || isApp {
        let workingDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: workingDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: workingDir) }

        let appURL = isIPA ? try FileManager.default.unzipAppBundle(at: targetURL, to: workingDir) : targetURL
        guard let app = AppBundle(fileURL: appURL) else {
            print("Error: Unable to parse AppBundle at \(appURL.path)")
            exit(1)
        }

        print("========================================")
        print("App Bundle Information")
        print("========================================")
        print("Name:                \(app.name)")
        print("Bundle ID:           \(app.bundleIdentifier)")
        print("Version:             \(app.version)")
        print("Executable:          \(app.executableName)")
        print("App Extensions:      \(app.appExtensions.count)")
        for ext in app.appExtensions {
            print("  * \(ext.name) (\(ext.bundleIdentifier))")
        }

        let profileURL = app.fileURL.appendingPathComponent("embedded.mobileprovision")
        if FileManager.default.fileExists(atPath: profileURL.path),
           let profData = try? Data(contentsOf: profileURL),
           let profile = try? ProvisioningProfile(data: profData) {
            print("\nEmbedded Provisioning Profile")
            print("Name:                \(profile.name)")
            print("Team:                \(profile.teamName) (\(profile.teamIdentifier))")
            print("Profile UUID:        \(profile.uuid)")
            print("Expiration:          \(profile.expirationDate)")
            print("Devices:             \(profile.devices.count) registered")
            if dumpEntitlements {
                print("\nProfile Entitlements:")
                for (k, v) in profile.entitlements {
                    print("  \(k): \(v)")
                }
            }
        }
    } else {
        let execURL: URL
        if isDir.boolValue {
            guard let exec = CodeSignKit.MachOParser.findExecutable(at: targetURL) else {
                print("Error: Could not find executable inside bundle \(target)")
                exit(1)
            }
            execURL = exec
        } else {
            execURL = targetURL
        }

        guard let parser = try? CodeSignKit.MachOParser(url: execURL) else {
            print("Error: Failed to parse Mach-O binary at \(execURL.path)")
            exit(1)
        }

        if dumpEntitlements {
            if let xml = try? parser.entitlements() {
                print(xml)
            } else {
                print("No XML entitlements found in binary.")
            }
        } else if dumpRequirements {
            if let req = try? parser.requirements() {
                print(req)
            } else {
                print("No Designated Requirements found in binary.")
            }
        } else {
            print("Executable=\(execURL.path)")
            if let ident = parser.bundleIdentifier() {
                print("Identifier=\(ident)")
            }
            if let team = parser.teamID() {
                print("TeamIdentifier=\(team)")
            }
            let cdHashes = parser.getCDHashes()
            if !cdHashes.isEmpty {
                print("CDHash=\(cdHashes[0])")
            }
            let archs = parser.architectures()
            if !archs.isEmpty {
                print("Architectures=\(archs.joined(separator: " "))")
            }
        }
    }
}

func handleProfile(args: [String]) throws {
    guard args.count >= 2 else {
        print("""
        Usage:
          sidesign profile dump <path/to/profile.mobileprovision>
          sidesign profile validate <path/to/profile.mobileprovision>
        """)
        exit(1)
    }

    let action = args[0]
    let path = args[1]
    let fileURL = URL(fileURLWithPath: path)
    let data = try Data(contentsOf: fileURL)
    let profile = try ProvisioningProfile(data: data)

    switch action {
    case "dump", "inspect":
        print("========================================")
        print("Provisioning Profile Details")
        print("========================================")
        print("Name:                \(profile.name)")
        print("App Bundle ID:       \(profile.bundleIdentifier)")
        print("Team:                \(profile.teamName) (\(profile.teamIdentifier))")
        print("UUID:                \(profile.uuid)")
        print("Created Date:        \(profile.creationDate)")
        print("Expiration Date:     \(profile.expirationDate)")
        print("Certificates:        \(profile.certificates.count)")
        for cert in profile.certificates {
            print("  * \(cert.commonName ?? "Certificate") [\(cert.serialNumber)]")
        }
        print("Devices:             \(profile.devices.count)")
        for dev in profile.devices {
            print("  * \(dev)")
        }
        print("\nEntitlements:")
        for (k, v) in profile.entitlements {
            print("  \(k): \(v)")
        }

    case "validate":
        let isExpired = profile.expirationDate < Date()
        if isExpired {
            print("Profile is EXPIRED on \(profile.expirationDate).")
            exit(1)
        } else {
            print("Profile is VALID (expires on \(profile.expirationDate)).")
        }

    default:
        print("Unknown profile action: \(action)")
        exit(1)
    }
}

func handleExtensions(args: [String]) throws {
    guard args.count >= 2 else {
        print("""
        Usage:
          sidesign extensions list <app_or_ipa>
          sidesign extensions remove <app_or_ipa> [--all | --id <bundle_id>] [--output <path>]
        """)
        exit(1)
    }

    let action = args[0]
    let target = args[1]
    let targetURL = URL(fileURLWithPath: target)
    let isIPA = targetURL.pathExtension.lowercased() == "ipa"

    let workingDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: workingDir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: workingDir) }

    let appURL = isIPA ? try FileManager.default.unzipAppBundle(at: targetURL, to: workingDir) : targetURL
    guard let app = AppBundle(fileURL: appURL) else {
        print("Error: Failed to parse AppBundle at \(appURL.path)")
        exit(1)
    }

    switch action {
    case "list":
        print("App Extensions in \(app.name): (\(app.appExtensions.count))")
        for ext in app.appExtensions {
            print("  * \(ext.name) [\(ext.bundleIdentifier)]")
        }

    case "remove":
        var removeAll = false
        var targetID: String?
        var outputPath: String?

        var idx = 2
        while idx < args.count {
            let a = args[idx]
            if a == "--all" { removeAll = true }
            else if a == "--id" || a == "--bundle-id" {
                if idx + 1 < args.count { targetID = args[idx + 1]; idx += 1 }
            } else if a == "--output" || a == "-o" {
                if idx + 1 < args.count { outputPath = args[idx + 1]; idx += 1 }
            }
            idx += 1
        }

        for ext in app.appExtensions {
            if removeAll || ext.bundleIdentifier == targetID {
                print("[Remove] Removing extension: \(ext.name) (\(ext.bundleIdentifier))...")
                try FileManager.default.removeItem(at: ext.fileURL)
            }
        }

        if isIPA {
            let finalOutURL: URL
            if let outputPath = outputPath {
                finalOutURL = URL(fileURLWithPath: outputPath)
            } else {
                let outName = targetURL.deletingPathExtension().lastPathComponent + "_no_ext.ipa"
                finalOutURL = targetURL.deletingLastPathComponent().appendingPathComponent(outName)
            }
            let zippedIPA = try FileManager.default.zipAppBundle(at: appURL, compressionLevel: .fastest)
            if FileManager.default.fileExists(atPath: finalOutURL.path) {
                try FileManager.default.removeItem(at: finalOutURL)
            }
            try FileManager.default.moveItem(at: zippedIPA, to: finalOutURL)
            print("Saved modified IPA: \(finalOutURL.path)")
        } else {
            print("Successfully modified App Bundle: \(appURL.path)")
        }

    default:
        print("Unknown extensions action: \(action)")
        exit(1)
    }
}

func handleArchive(args: [String]) throws {
    guard args.count >= 2 else {
        print("""
        Usage:
          sidesign archive unzip <input.ipa> [--output <directory>]
          sidesign archive zip <input.app> [--output <output.ipa>]
        """)
        exit(1)
    }

    let action = args[0]
    let input = args[1]
    let inputURL = URL(fileURLWithPath: input)

    var outputPath: String?
    if args.count >= 4 && (args[2] == "--output" || args[2] == "-o") {
        outputPath = args[3]
    }

    switch action {
    case "unzip":
        let destDir = outputPath.map { URL(fileURLWithPath: $0) } ?? inputURL.deletingLastPathComponent()
        print("[Unpack] Unpacking \(inputURL.lastPathComponent) to \(destDir.path)...")
        let appURL = try FileManager.default.unzipAppBundle(at: inputURL, to: destDir)
        print("Extracted app bundle: \(appURL.path)")

    case "zip":
        let outIPA = outputPath.map { URL(fileURLWithPath: $0) } ?? inputURL.deletingLastPathComponent().appendingPathComponent(inputURL.deletingPathExtension().lastPathComponent + ".ipa")
        print("[Package] Packaging \(inputURL.lastPathComponent) to \(outIPA.path)...")
        let createdIPA = try FileManager.default.zipAppBundle(at: inputURL, compressionLevel: .fastest)
        if createdIPA != outIPA {
            if FileManager.default.fileExists(atPath: outIPA.path) {
                try FileManager.default.removeItem(at: outIPA)
            }
            try FileManager.default.moveItem(at: createdIPA, to: outIPA)
        }
        print("Created IPA: \(outIPA.path)")

    default:
        print("Unknown archive action: \(action)")
        exit(1)
    }
}

func handleRemoveSignature(args: [String]) throws {
    guard let target = args.first else {
        print("Usage: sidesign remove-signature <path_to_binary_or_bundle>")
        exit(1)
    }
    let targetURL = URL(fileURLWithPath: target)
    print("[Remove] Removing code signature from: \(targetURL.path)")
    guard let parser = try? CodeSignKit.MachOParser(url: targetURL) else {
        print("Error: Failed to parse binary at \(targetURL.path)")
        exit(1)
    }
    try parser.removeSignature()
    print("Successfully removed code signature.")
}

func handleAuth(args: [String]) async throws {
    guard !args.isEmpty else {
        print("""
        Usage:
          sidesign auth login --apple-id <email> [--password <pwd>] [--anisette-url <url>]
          sidesign auth teams --apple-id <email>
          sidesign auth devices list / register --name <name> --udid <udid>
          sidesign auth certs list / create / revoke --id <id>
          sidesign auth profiles list / fetch --bundle-id <id> --device <udid>
          sidesign auth appids list / register --name <name> --bundle-id <id>
        """)
        exit(1)
    }

    var appleID: String?
    var password: String?
    var anisetteURL: String?

    var i = 0
    while i < args.count {
        let a = args[i]
        if a == "--apple-id" || a == "-u" {
            if i + 1 < args.count { appleID = args[i + 1]; i += 1 }
        } else if a == "--password" || a == "-p" {
            if i + 1 < args.count { password = args[i + 1]; i += 1 }
        } else if a == "--anisette-url" || a == "--anisette" {
            if i + 1 < args.count { anisetteURL = args[i + 1]; i += 1 }
        }
        i += 1
    }

    guard let email = appleID else {
        print("Error: --apple-id <email> is required.")
        exit(1)
    }

    let pwd: String
    if let p = password {
        pwd = p
    } else {
        print("Enter password for \(email): ", terminator: "")
        guard let entered = readLine(strippingNewline: true), !entered.isEmpty else {
            print("Error: Password cannot be empty.")
            exit(1)
        }
        pwd = entered
    }

    print("Fetching Anisette data...")
    let anisetteData = try await fetchAnisette(from: anisetteURL)

    let portal = DeveloperPortalAPI()

    print("Authenticating with Apple Developer Portal...")
    let session = try await portal.authenticate(
        appleID: email,
        password: pwd,
        anisetteData: anisetteData,
        xcodeVersion: "15.0"
    ) { mode, completion in
        handleCLI2FA(mode: mode, completion: completion)
    }

    print("Authentication successful! Logged in as: \(session.account.name)")

    let action = args[0]
    if action == "login" {
        print("Session DSID: \(session.account.identifier)")
        return
    }

    switch action {
    case "teams":
        print("\nDeveloper Teams:")
        let teams = try await portal.fetchTeams(for: session.account, session: session)
        for t in teams {
            print("  * \(t.name) (ID: \(t.identifier), Type: \(t.type.rawValue))")
        }

    case "devices":
        let teams = try await portal.fetchTeams(for: session.account, session: session)
        guard let team = teams.first else {
            print("Error: No teams found on this account.")
            return
        }
        if args.contains("register") {
            var name: String?
            var udid: String?
            var idx = 1
            while idx < args.count {
                if args[idx] == "--name" && idx + 1 < args.count { name = args[idx + 1]; idx += 1 }
                if args[idx] == "--udid" && idx + 1 < args.count { udid = args[idx + 1]; idx += 1 }
                idx += 1
            }
            guard let name = name, let udid = udid else {
                print("Usage: sidesign auth devices register --name <name> --udid <udid>")
                exit(1)
            }
            print("Registering device \(name) (\(udid))...")
            let device = try await portal.registerDevice(name: name, identifier: udid, type: .iPhone, team: team, session: session)
            print("Successfully registered device: \(device.name) (\(device.identifier))")
        } else {
            print("\nRegistered Devices for team '\(team.name)':")
            let devices = try await portal.fetchDevices(for: team, session: session)
            for d in devices {
                print("  * \(d.name) [\(d.identifier)] (\(d.type.description))")
            }
        }

    case "certs":
        let teams = try await portal.fetchTeams(for: session.account, session: session)
        guard let team = teams.first else {
            print("Error: No teams found on this account.")
            return
        }
        if args.contains("create") {
            print("Creating new Development Certificate...")
            let keyStore = try await portal.addCertificate(machineName: "Mac", to: team, session: session)
            print("Successfully created certificate: \(keyStore.certificate.name) (Serial: \(keyStore.certificate.serialNumber))")
        } else if args.contains("revoke") {
            var certID: String?
            var idx = 1
            while idx < args.count {
                if args[idx] == "--id" && idx + 1 < args.count { certID = args[idx + 1]; idx += 1 }
                idx += 1
            }
            guard let certID = certID else {
                print("Usage: sidesign auth certs revoke --id <cert_id>")
                exit(1)
            }
            print("Revoking certificate \(certID)...")
            let certs = try await portal.fetchCertificates(for: team, session: session)
            if let targetCert = certs.first(where: { $0.identifier == certID }) {
                try await portal.revokeCertificate(targetCert, team: team, session: session)
                print("Certificate revoked successfully.")
            } else {
                print("Error: Certificate ID not found.")
            }
        } else {
            print("\nCertificates for team '\(team.name)':")
            let certs = try await portal.fetchCertificates(for: team, session: session)
            for c in certs {
                print("  * \(c.name) [ID: \(c.identifier), Serial: \(c.serialNumber)]")
            }
        }

    case "appids":
        let teams = try await portal.fetchTeams(for: session.account, session: session)
        guard let team = teams.first else { return }
        print("\nApp IDs for team '\(team.name)':")
        let appIDs = try await portal.fetchAppIDs(for: team, session: session)
        for a in appIDs {
            print("  * \(a.name) [\(a.bundleIdentifier)] (ID: \(a.identifier))")
        }

    case "profiles":
        let teams = try await portal.fetchTeams(for: session.account, session: session)
        guard let team = teams.first else { return }
        print("\nProvisioning Profiles for team '\(team.name)':")
        let profiles = try await portal.fetchProvisioningProfiles(for: team, session: session)
        for p in profiles {
            print("  * \(p.name) [BundleID: \(p.bundleIdentifier), UUID: \(p.uuid)]")
        }

    default:
        print("Unknown auth subcommand: \(action)")
        exit(1)
    }
}

func handleCLI2FA(mode: TwoFactorMode, completion: @escaping (TwoFactorAction) -> Void) {
    switch mode {
    case .trustedDevice(let error):
        if let error = error {
            print("\n[2FA] Verification Error: \(error)")
            print("Press [Enter] to retry code entry, or 'c' to cancel: ", terminator: "")
            if let input = readLine(strippingNewline: true), input.lowercased() == "c" {
                completion(.cancel)
                return
            }
        }
        print("\nEnter 6-digit verification code from your Apple device (or 'p' for phone call/SMS, 'c' to cancel): ", terminator: "")
        guard let code = readLine(strippingNewline: true), !code.isEmpty else {
            completion(.cancel)
            return
        }
        if code.lowercased() == "c" {
            completion(.cancel)
        } else if code.lowercased() == "p" {
            completion(.requestPhone(id: "1", mode: .sms))
        } else {
            completion(.code(code))
        }

    case .sms(let phoneNumbers, let activeID, let error):
        if let error = error {
            print("\n[SMS] Verification Error: \(error)")
            print("Press [Enter] to retry code entry, or 'c' to cancel: ", terminator: "")
            if let input = readLine(strippingNewline: true), input.lowercased() == "c" {
                completion(.cancel)
                return
            }
        }
        let activePhone = phoneNumbers.first(where: { $0.id == activeID })?.number ?? "phone"
        print("\nEnter 6-digit code sent via SMS to \(activePhone) (or 'v' for voice call, 'r' to resend, 'c' to cancel): ", terminator: "")
        guard let code = readLine(strippingNewline: true), !code.isEmpty else {
            completion(.cancel)
            return
        }
        if code.lowercased() == "c" {
            completion(.cancel)
        } else if code.lowercased() == "v" {
            completion(.requestPhone(id: activeID, mode: .voice))
        } else if code.lowercased() == "r" {
            completion(.requestPhone(id: activeID, mode: .sms))
        } else {
            completion(.code(code))
        }

    case .voice(let phoneNumbers, let activeID, let error):
        if let error = error {
            print("\n[Voice] Verification Error: \(error)")
            print("Press [Enter] to retry code entry, or 'c' to cancel: ", terminator: "")
            if let input = readLine(strippingNewline: true), input.lowercased() == "c" {
                completion(.cancel)
                return
            }
        }
        let activePhone = phoneNumbers.first(where: { $0.id == activeID })?.number ?? "phone"
        print("\nEnter 6-digit code from phone call to \(activePhone) (or 's' for SMS, 'r' to call again, 'c' to cancel): ", terminator: "")
        guard let code = readLine(strippingNewline: true), !code.isEmpty else {
            completion(.cancel)
            return
        }
        if code.lowercased() == "c" {
            completion(.cancel)
        } else if code.lowercased() == "s" {
            completion(.requestPhone(id: activeID, mode: .sms))
        } else if code.lowercased() == "r" {
            completion(.requestPhone(id: activeID, mode: .voice))
        } else {
            completion(.code(code))
        }
    }
}

func handleAnisette(args: [String]) async throws {
    var serverURL: String?
    var asJSON = false

    for a in args {
        if a == "--json" { asJSON = true }
        else if a.hasPrefix("http") { serverURL = a }
    }

    print("Fetching Anisette data...")
    let data = try await fetchAnisette(from: serverURL)
    if asJSON {
        let jsonDict = data.json()
        if let jsonData = try? JSONSerialization.data(withJSONObject: jsonDict, options: .prettyPrinted),
           let str = String(data: jsonData, encoding: .utf8) {
            print(str)
        }
    } else {
        print("MachineID:              \(data.machineID)")
        print("OneTimePassword:        \(data.oneTimePassword)")
        print("LocalUserID:            \(data.localUserID)")
        print("RoutingInfo:            \(data.routingInfo)")
        print("DeviceUniqueIdentifier: \(data.deviceUniqueIdentifier)")
        print("DeviceSerialNumber:     \(data.deviceSerialNumber)")
        print("Date:                   \(data.date)")
        print("Locale:                 \(data.locale.identifier)")
        print("TimeZone:               \(data.timeZone.identifier)")
    }
}

func fetchAnisette(from urlString: String?) async throws -> AnisetteData {
    if let urlStr = urlString, let url = URL(string: urlStr) {
        let (data, response) = try await URLSession.shared.data(from: url)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else {
            throw ServerError.badServerResponse(reason: "Anisette server returned non-200", jsonPayload: nil)
        }
        let json = try JSONSerialization.jsonObject(with: data) as? [String: String] ?? [:]
        guard let anisette = AnisetteData(json: json) else {
            throw ServerError.invalidResponseFormat(rawPayload: String(data: data, encoding: .utf8) ?? "")
        }
        return anisette
    }

    return AnisetteData(
        machineID: UUID().uuidString.uppercased(),
        oneTimePassword: UUID().uuidString.uppercased(),
        localUserID: UUID().uuidString.uppercased(),
        routingInfo: 0x01,
        deviceUniqueIdentifier: UUID().uuidString.uppercased(),
        deviceSerialNumber: "0",
        deviceDescription: "Mac",
        date: Date(),
        locale: Locale.current,
        timeZone: TimeZone.current
    )
}

// Top-level entry execution
let args = Array(CommandLine.arguments.dropFirst())

if args.isEmpty || args.contains("-h") || args.contains("--help") || args.contains("help") {
    printUsage()
    exit(0)
}

if args.contains("--verbose") || args.contains("-v") || args.contains("-vv") || args.contains("--debug") {
    Logging.setLogging(true)
}

let command = args[0]
let subArgs = Array(args.dropFirst())

do {
    switch command {
    case "sign", "-s", "--sign":
        try await handleSign(args: subArgs)
    case "verify":
        try handleVerify(args: subArgs)
    case "display", "inspect", "-d", "--display":
        try handleDisplay(args: subArgs)
    case "profile":
        try handleProfile(args: subArgs)
    case "extensions":
        try handleExtensions(args: subArgs)
    case "archive":
        try handleArchive(args: subArgs)
    case "auth":
        try await handleAuth(args: subArgs)
    case "anisette":
        try await handleAnisette(args: subArgs)
    case "remove-signature", "--remove-signature":
        try handleRemoveSignature(args: subArgs)
    default:
        if FileManager.default.fileExists(atPath: command) {
            try await handleSign(args: [command] + subArgs)
        } else {
            print("Error: Unknown command '\(command)'.")
            printUsage()
            exit(1)
        }
    }
} catch {
    print("\nError: \(error.localizedDescription)")
    exit(1)
}
