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
import AnisetteKit

extension DeviceType {
    var displayName: String {
        if contains(.iPhone) { return "iPhone" }
        if contains(.iPad) { return "iPad" }
        if contains(.appleTV) { return "Apple TV" }
        if contains(.appleWatch) { return "Apple Watch" }
        if contains(.mac) { return "Mac" }
        if contains(.visionPro) { return "Apple Vision Pro" }
        return "Device"
    }
}

func printUsage() {
    print("""
    sidesign - Advanced App Signing, CodeSignKit, and Apple Developer Portal CLI

    Usage:
      sidesign <command> [options]

    Commands:
      sign                  Sign an IPA, .app bundle, framework, dylib, or Mach-O binary
      verify                Verify code signatures and binary integrity
      display / inspect     Inspect signatures, entitlements, Mach-O slices, or bundle metadata
      profile               Inspect, dump, or validate .mobileprovision profiles
      extensions            List or remove App Extensions from an IPA or .app bundle
      archive               Unzip IPAs to .app bundles or repackage .app bundles to IPAs
      auth                  Apple ID authentication, 2FA, and Developer Portal operations
      anisette              Generate Anisette headers from remote or local ADI providers
      p12                   Create or extract PKCS#12 (.p12) identity bundles
      csr                   Generate Certificate Signing Requests (.csr) and RSA private keys
      remove-signature      Remove code signature from Mach-O binary or bundle

    Global Options:
      --verbose, -v         Enable verbose logging
      --debug, -d           Enable debug logging
      --help, -h            Show help and usage information

    Examples:
      # Sign an IPA with P12 and Mobileprovision:
      sidesign sign app.ipa --p12 dev.p12 --password secret --profile dev.mobileprovision --output signed.ipa

      # Inspect an App Bundle or Mach-O Binary:
      sidesign inspect app.ipa --entitlements

      # Dump Provisioning Profile details:
      sidesign profile dump embedded.mobileprovision

      # Remove extensions from an IPA:
      sidesign extensions remove app.ipa --all --output app_no_ext.ipa

      # Apple Developer Portal login & 2FA:
      sidesign auth login --apple-id developer@example.com

      # Login with interactive Anisette server selection:
      sidesign auth login --apple-id developer@example.com --select-server

      # List available public Anisette servers:
      sidesign anisette servers

      # Interactively pick a server from the public list:
      sidesign anisette --select-server

      # Fetch Anisette headers via remote ODA package:
      sidesign anisette --oda https://example.com/oda.json

      # Register a new device UDID:
      sidesign auth devices register --name "My iPhone" --udid <DEVICE_UDID> --apple-id developer@example.com

      # Register an App ID:
      sidesign auth appids register --name "MyApp" --bundle-id "com.example.myapp" --apple-id developer@example.com

      # Create an App Group:
      sidesign auth appgroups create --name "MyAppGroup" --group-id "group.com.example.myapp" --apple-id developer@example.com

      # Download a Provisioning Profile:
      sidesign auth profiles download --bundle-id "com.example.myapp" --output dev.mobileprovision --apple-id developer@example.com

      # Generate a Certificate Signing Request:
      sidesign csr create --name "John Doe" --org "My Org" --output-csr request.csr --output-key private.key

      # Package Certificate + Key into P12:
      sidesign p12 create --cert cert.der --key private.key --password secret --output dev.p12

      # Generate Anisette headers using local ADI libraries:
      sidesign anisette --local /path/to/adi/Libraries --json
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
            if let profile = ProvisioningProfile(data: profData) {
                profiles.append(profile)
            } else {
                print("Error: Could not parse provisioning profile at \(profilePath)")
                exit(1)
            }
        }

        let effectiveTeamID = teamID ?? profiles.first?.teamIdentifier ?? keyStore.certificate.organizationalUnit ?? "UNKNOWN"
        let team = Team(identifier: effectiveTeamID, name: keyStore.certificate.name, type: .free)

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
            let cmsSigner = CodeSignKit.CMSSigner(p12Data: p12Data, password: password)
            let finalBundleID = bundleID ?? targetURL.lastPathComponent

            let signer = CodeSignKit.MachOSigner(
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

        let executableName = app.bundle.infoDictionary?["CFBundleExecutable"] as? String ?? app.name

        print("========================================")
        print("App Bundle Information")
        print("========================================")
        print("Name:                \(app.name)")
        print("Bundle ID:           \(app.bundleIdentifier)")
        print("Version:             \(app.version)")
        print("Executable:          \(executableName)")
        print("App Extensions:      \(app.appExtensions.count)")
        for ext in app.appExtensions {
            print("  * \(ext.name) (\(ext.bundleIdentifier))")
        }

        let profileURL = app.fileURL.appendingPathComponent("embedded.mobileprovision")
        if FileManager.default.fileExists(atPath: profileURL.path),
           let profData = try? Data(contentsOf: profileURL),
           let profile = ProvisioningProfile(data: profData) {
            print("\nEmbedded Provisioning Profile")
            print("Name:                \(profile.name)")
            print("Team:                \(profile.teamName) (\(profile.teamIdentifier))")
            print("Profile UUID:        \(profile.uuid)")
            print("Expiration:          \(profile.expirationDate)")
            print("Devices:             \(profile.deviceIDs.count) registered")
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
    guard let profile = ProvisioningProfile(data: data) else {
        print("Error: Could not parse provisioning profile at \(path)")
        exit(1)
    }

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
        print("Devices:             \(profile.deviceIDs.count)")
        for dev in profile.deviceIDs {
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
    try CodeSignKit.CodeSigner.removeSignature(at: targetURL)
    print("Successfully removed code signature.")
}

func handleAuth(args: [String]) async throws {
    guard !args.isEmpty else {
        print("""
        Usage:
          sidesign auth login --apple-id <email> [--password <pwd>] [--anisette-url <url>] [--local-anisette <dir>]
          sidesign auth teams --apple-id <email>
          sidesign auth devices list / register --name <name> --udid <udid>
          sidesign auth certs list / create / revoke --id <id>
          sidesign auth appids list / register --name <name> --bundle-id <id> / delete --id <id>
          sidesign auth appgroups list / create --name <name> --group-id <id> / assign --app-id <id> --group-id <id>
          sidesign auth profiles list / download --bundle-id <id> [--output <path>] / delete --id <id>
        """)
        exit(1)
    }

    var appleID: String?
    var password: String?
    var anisetteURL: String?
    var localAnisetteDir: String?
    var odaURL: String?
    var selectServer = false
    var strict = false

    var sourceURLStr: String?

    var i = 0
    while i < args.count {
        let a = args[i]
        if a == "--apple-id" || a == "-u" {
            if i + 1 < args.count { appleID = args[i + 1]; i += 1 }
        } else if a == "--password" || a == "-p" {
            if i + 1 < args.count { password = args[i + 1]; i += 1 }
        } else if a == "--anisette-url" || a == "--anisette" || a == "--server" {
            if i + 1 < args.count { anisetteURL = args[i + 1]; i += 1 }
        } else if a == "--local-anisette" || a == "--local-adi" || a == "--local" {
            if i + 1 < args.count { localAnisetteDir = args[i + 1]; i += 1 }
        } else if a == "--oda" {
            if i + 1 < args.count { odaURL = args[i + 1]; i += 1 }
        } else if a == "--source" || a == "--list" {
            if i + 1 < args.count { sourceURLStr = args[i + 1]; i += 1 }
        } else if a == "--select-server" || a == "-s" {
            selectServer = true
        } else if a == "--strict" {
            strict = true
        }
        i += 1
    }

    if selectServer {
        anisetteURL = try await selectAnisetteServerInteractively(sourceURLString: sourceURLStr)
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

    let mode: AnisetteMode
    if let localDir = localAnisetteDir {
        mode = .localODA(libsDir: URL(fileURLWithPath: localDir))
    } else if let odaStr = odaURL, let odaURL = URL(string: odaStr) {
        mode = .remoteODA(sourceURL: odaURL)
    } else if let sUrl = anisetteURL, let url = URL(string: sUrl) {
        if strict {
            let isValid = await AnisetteDataProvider.validateServer(url: url, strict: true)
            guard isValid else {
                print("Error: Strict validation failed for remote server '\(url.absoluteString)'. Endpoint is not ready or not returning valid Anisette payload.")
                exit(1)
            }
        }
        mode = .remote(server: url)
    } else {
        print("Error: An Anisette mode is required. Specify one of:")
        print("  --server <url>                 (Direct remote Anisette server)")
        print("  --local <dir>                  (Local ADI library directory)")
        print("  --oda <url>                    (Remote ODA package / catalog URL)")
        print("  --select-server --source <url> (Select interactively from catalog)")
        exit(1)
    }

    print("Fetching Anisette data...")
    let provider = AnisetteDataProvider(mode: mode)
    let (anisetteData, _) = try await provider.fetchAnisetteData()

    let portal = DeveloperPortal()

    print("Authenticating with Apple Developer Portal...")
    let authSession = try await portal.authenticate(
        appleID: email,
        password: pwd,
        anisetteData: anisetteData,
        xcodeVersion: "15.0"
    ) { mode, completion in
        handleCLI2FA(mode: mode, completion: completion)
    }

    let account = authSession.account
    let session = authSession.session

    print("Authentication successful! Logged in as: \(account.name)")

    let action = args[0]
    if action == "login" {
        print("Session DSID: \(account.identifier)")
        return
    }

    switch action {
    case "teams":
        print("\nDeveloper Teams:")
        let teams = try await portal.fetchTeams(for: account, session: session)
        for t in teams {
            print("  * \(t.name) (ID: \(t.identifier), Type: \(t.type.rawValue))")
        }

    case "devices":
        let teams = try await portal.fetchTeams(for: account, session: session)
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
            let device = try await portal.registerDevice(name: name, identifier: udid, type: DeviceType.iPhone, team: team, session: session)
            print("Successfully registered device: \(device.name) (\(device.identifier))")
        } else {
            print("\nRegistered Devices for team '\(team.name)':")
            let devices = try await portal.fetchDevices(for: team, session: session)
            for d in devices {
                print("  * \(d.name) [\(d.identifier)] (\(d.type.displayName))")
            }
        }

    case "certs":
        let teams = try await portal.fetchTeams(for: account, session: session)
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
                _ = try await portal.revokeCertificate(targetCert, for: team, session: session)
                print("Certificate revoked successfully.")
            } else {
                print("Error: Certificate ID not found.")
            }
        } else {
            print("\nCertificates for team '\(team.name)':")
            let certs = try await portal.fetchCertificates(for: team, session: session)
            for c in certs {
                print("  * \(c.name) [ID: \(c.identifier ?? "unknown"), Serial: \(c.serialNumber)]")
            }
        }

    case "appids":
        let teams = try await portal.fetchTeams(for: account, session: session)
        guard let team = teams.first else { return }
        if args.contains("register") || args.contains("create") {
            var name: String?
            var bundleID: String?
            var idx = 1
            while idx < args.count {
                if args[idx] == "--name" && idx + 1 < args.count { name = args[idx + 1]; idx += 1 }
                if (args[idx] == "--bundle-id" || args[idx] == "-i") && idx + 1 < args.count { bundleID = args[idx + 1]; idx += 1 }
                idx += 1
            }
            guard let name = name, let bundleID = bundleID else {
                print("Usage: sidesign auth appids register --name <name> --bundle-id <bundle_id>")
                exit(1)
            }
            print("Registering App ID '\(name)' (\(bundleID))...")
            let appID = try await portal.addAppID(withName: name, bundleIdentifier: bundleID, team: team, session: session)
            print("Successfully created App ID: \(appID.name) (\(appID.bundleIdentifier), ID: \(appID.identifier))")
        } else if args.contains("delete") {
            var targetID: String?
            var idx = 1
            while idx < args.count {
                if args[idx] == "--id" && idx + 1 < args.count { targetID = args[idx + 1]; idx += 1 }
                idx += 1
            }
            guard let targetID = targetID else {
                print("Usage: sidesign auth appids delete --id <app_id>")
                exit(1)
            }
            let appIDs = try await portal.fetchAppIDs(for: team, session: session)
            if let target = appIDs.first(where: { $0.identifier == targetID || $0.bundleIdentifier == targetID }) {
                _ = try await portal.deleteAppID(target, for: team, session: session)
                print("Successfully deleted App ID: \(target.name) (\(target.bundleIdentifier))")
            } else {
                print("Error: App ID '\(targetID)' not found.")
            }
        } else {
            print("\nApp IDs for team '\(team.name)':")
            let appIDs = try await portal.fetchAppIDs(for: team, session: session)
            for a in appIDs {
                print("  * \(a.name) [\(a.bundleIdentifier)] (ID: \(a.identifier))")
            }
        }

    case "appgroups":
        let teams = try await portal.fetchTeams(for: account, session: session)
        guard let team = teams.first else { return }
        if args.contains("create") || args.contains("add") {
            var name: String?
            var groupID: String?
            var idx = 1
            while idx < args.count {
                if args[idx] == "--name" && idx + 1 < args.count { name = args[idx + 1]; idx += 1 }
                if args[idx] == "--group-id" && idx + 1 < args.count { groupID = args[idx + 1]; idx += 1 }
                idx += 1
            }
            guard let name = name, let groupID = groupID else {
                print("Usage: sidesign auth appgroups create --name <name> --group-id <group_id>")
                exit(1)
            }
            print("Creating App Group '\(name)' (\(groupID))...")
            let group = try await portal.addAppGroup(name: name, groupIdentifier: groupID, team: team, session: session)
            print("Successfully created App Group: \(group.name) (\(group.identifier))")
        } else if args.contains("assign") {
            var appIDStr: String?
            var groupIDStr: String?
            var idx = 1
            while idx < args.count {
                if args[idx] == "--app-id" && idx + 1 < args.count { appIDStr = args[idx + 1]; idx += 1 }
                if args[idx] == "--group-id" && idx + 1 < args.count { groupIDStr = args[idx + 1]; idx += 1 }
                idx += 1
            }
            guard let appIDStr = appIDStr, let groupIDStr = groupIDStr else {
                print("Usage: sidesign auth appgroups assign --app-id <app_id> --group-id <group_id>")
                exit(1)
            }
            let appIDs = try await portal.fetchAppIDs(for: team, session: session)
            guard let targetAppID = appIDs.first(where: { $0.identifier == appIDStr || $0.bundleIdentifier == appIDStr }) else {
                print("Error: App ID '\(appIDStr)' not found.")
                exit(1)
            }
            let groups = try await portal.fetchAppGroups(for: team, session: session)
            guard let targetGroup = groups.first(where: { $0.identifier == groupIDStr || $0.groupID == groupIDStr }) else {
                print("Error: App Group '\(groupIDStr)' not found.")
                exit(1)
            }
            let updated = try await portal.assignAppGroups([targetGroup], to: targetAppID, team: team, session: session)
            print("Successfully assigned group to App ID: \(updated.name)")
        } else {
            print("\nApp Groups for team '\(team.name)':")
            let groups = try await portal.fetchAppGroups(for: team, session: session)
            for g in groups {
                print("  * \(g.name) [\(g.identifier)] (ID: \(g.groupID))")
            }
        }

    case "profiles":
        let teams = try await portal.fetchTeams(for: account, session: session)
        guard let team = teams.first else { return }
        if args.contains("download") || args.contains("fetch") {
            var bundleIDStr: String?
            var outputPath: String?
            var idx = 1
            while idx < args.count {
                if (args[idx] == "--bundle-id" || args[idx] == "-i") && idx + 1 < args.count { bundleIDStr = args[idx + 1]; idx += 1 }
                if (args[idx] == "--output" || args[idx] == "-o") && idx + 1 < args.count { outputPath = args[idx + 1]; idx += 1 }
                idx += 1
            }
            guard let bundleID = bundleIDStr else {
                print("Usage: sidesign auth profiles download --bundle-id <bundle_id> [--output <path>]")
                exit(1)
            }
            let appIDs = try await portal.fetchAppIDs(for: team, session: session)
            guard let targetAppID = appIDs.first(where: { $0.bundleIdentifier == bundleID || $0.identifier == bundleID }) else {
                print("Error: App ID '\(bundleID)' not found.")
                exit(1)
            }
            print("Downloading Provisioning Profile for \(targetAppID.bundleIdentifier)...")
            let profile = try await portal.downloadProvisioningProfile(for: targetAppID, deviceType: .iPhone, team: team, session: session)
            if let out = outputPath {
                let outURL = URL(fileURLWithPath: out)
                try profile.data.write(to: outURL)
                print("Profile saved to: \(outURL.path)")
            } else {
                print("Successfully downloaded profile: \(profile.name) (UUID: \(profile.uuid))")
            }
        } else if args.contains("delete") {
            var profileID: String?
            var idx = 1
            while idx < args.count {
                if args[idx] == "--id" && idx + 1 < args.count { profileID = args[idx + 1]; idx += 1 }
                idx += 1
            }
            guard let profID = profileID else {
                print("Usage: sidesign auth profiles delete --id <profile_id_or_uuid>")
                exit(1)
            }
            let profiles = try await portal.fetchProvisioningProfiles(for: team, session: session)
            if let target = profiles.first(where: { $0.identifier == profID || $0.uuid.uuidString == profID }) {
                _ = try await portal.deleteProvisioningProfile(target, team: team, session: session)
                print("Successfully deleted Provisioning Profile: \(target.name)")
            } else {
                print("Error: Provisioning Profile '\(profID)' not found.")
            }
        } else {
            print("\nProvisioning Profiles for team '\(team.name)':")
            let profiles = try await portal.fetchProvisioningProfiles(for: team, session: session)
            for p in profiles {
                print("  * \(p.name) [BundleID: \(p.bundleIdentifier), UUID: \(p.uuid)]")
            }
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
                completion(TwoFactorAction.cancel)
                return
            }
        }
        print("\nEnter 6-digit verification code from your Apple device (or 'p' for phone call/SMS, 'c' to cancel): ", terminator: "")
        guard let code = readLine(strippingNewline: true), !code.isEmpty else {
            completion(TwoFactorAction.cancel)
            return
        }
        if code.lowercased() == "c" {
            completion(TwoFactorAction.cancel)
        } else if code.lowercased() == "p" {
            completion(TwoFactorAction.requestPhone(id: "1", mode: TwoFactorDeliveryMode.sms))
        } else {
            completion(TwoFactorAction.code(code))
        }

    case .sms(let phoneNumbers, let activeID, let error):
        if let error = error {
            print("\n[SMS] Verification Error: \(error)")
            print("Press [Enter] to retry code entry, or 'c' to cancel: ", terminator: "")
            if let input = readLine(strippingNewline: true), input.lowercased() == "c" {
                completion(TwoFactorAction.cancel)
                return
            }
        }
        let activePhone = phoneNumbers.first(where: { $0.id == activeID })?.number ?? "phone"
        print("\nEnter 6-digit code sent via SMS to \(activePhone) (or 'v' for voice call, 'r' to resend, 'c' to cancel): ", terminator: "")
        guard let code = readLine(strippingNewline: true), !code.isEmpty else {
            completion(TwoFactorAction.cancel)
            return
        }
        if code.lowercased() == "c" {
            completion(TwoFactorAction.cancel)
        } else if code.lowercased() == "v" {
            completion(TwoFactorAction.requestPhone(id: activeID, mode: TwoFactorDeliveryMode.voice))
        } else if code.lowercased() == "r" {
            completion(TwoFactorAction.requestPhone(id: activeID, mode: TwoFactorDeliveryMode.sms))
        } else {
            completion(TwoFactorAction.code(code))
        }

    case .voice(let phoneNumbers, let activeID, let error):
        if let error = error {
            print("\n[Voice] Verification Error: \(error)")
            print("Press [Enter] to retry code entry, or 'c' to cancel: ", terminator: "")
            if let input = readLine(strippingNewline: true), input.lowercased() == "c" {
                completion(TwoFactorAction.cancel)
                return
            }
        }
        let activePhone = phoneNumbers.first(where: { $0.id == activeID })?.number ?? "phone"
        print("\nEnter 6-digit code from phone call to \(activePhone) (or 's' for SMS, 'r' to call again, 'c' to cancel): ", terminator: "")
        guard let code = readLine(strippingNewline: true), !code.isEmpty else {
            completion(TwoFactorAction.cancel)
            return
        }
        if code.lowercased() == "c" {
            completion(TwoFactorAction.cancel)
        } else if code.lowercased() == "s" {
            completion(TwoFactorAction.requestPhone(id: activeID, mode: TwoFactorDeliveryMode.sms))
        } else if code.lowercased() == "r" {
            completion(TwoFactorAction.requestPhone(id: activeID, mode: TwoFactorDeliveryMode.voice))
        } else {
            completion(TwoFactorAction.code(code))
        }
    }
}

func handleP12(args: [String]) throws {
    guard args.count >= 1 else {
        print("""
        Usage:
          sidesign p12 create --cert <cert.cer/der> --key <private.key> [--password <pwd>] --output <out.p12>
          sidesign p12 extract --input <in.p12> [--password <pwd>] --output-cert <cert.der> --output-key <key.der>
        """)
        exit(1)
    }

    let action = args[0]
    switch action {
    case "create":
        var certPath: String?
        var keyPath: String?
        var password: String?
        var outputPath: String?

        var idx = 1
        while idx < args.count {
            if args[idx] == "--cert" && idx + 1 < args.count { certPath = args[idx + 1]; idx += 1 }
            if args[idx] == "--key" && idx + 1 < args.count { keyPath = args[idx + 1]; idx += 1 }
            if (args[idx] == "--password" || args[idx] == "-p") && idx + 1 < args.count { password = args[idx + 1]; idx += 1 }
            if (args[idx] == "--output" || args[idx] == "-o") && idx + 1 < args.count { outputPath = args[idx + 1]; idx += 1 }
            idx += 1
        }

        guard let cert = certPath, let key = keyPath, let out = outputPath else {
            print("Usage: sidesign p12 create --cert <cert.cer> --key <key.key> [--password <pwd>] --output <out.p12>")
            exit(1)
        }

        let certData = try Data(contentsOf: URL(fileURLWithPath: cert))
        let keyData = try Data(contentsOf: URL(fileURLWithPath: key))
        let p12Data = try PKCS12Parser.create(cert: certData, key: keyData, password: password)
        try p12Data.write(to: URL(fileURLWithPath: out))
        print("Successfully created PKCS#12 bundle at: \(out)")

    case "extract":
        var inputPath: String?
        var password: String?
        var outCertPath: String?
        var outKeyPath: String?

        var idx = 1
        while idx < args.count {
            if (args[idx] == "--input" || args[idx] == "-i") && idx + 1 < args.count { inputPath = args[idx + 1]; idx += 1 }
            if (args[idx] == "--password" || args[idx] == "-p") && idx + 1 < args.count { password = args[idx + 1]; idx += 1 }
            if args[idx] == "--output-cert" && idx + 1 < args.count { outCertPath = args[idx + 1]; idx += 1 }
            if args[idx] == "--output-key" && idx + 1 < args.count { outKeyPath = args[idx + 1]; idx += 1 }
            idx += 1
        }

        guard let input = inputPath, let outCert = outCertPath, let outKey = outKeyPath else {
            print("Usage: sidesign p12 extract --input <in.p12> [--password <pwd>] --output-cert <cert.der> --output-key <key.der>")
            exit(1)
        }

        let p12Data = try Data(contentsOf: URL(fileURLWithPath: input))
        let result = try PKCS12Parser.extract(p12Data, password: password)
        try result.cert.write(to: URL(fileURLWithPath: outCert))
        try result.key.write(to: URL(fileURLWithPath: outKey))
        print("Successfully extracted certificate to \(outCert) and private key to \(outKey)")

    default:
        print("Unknown p12 action: \(action)")
        exit(1)
    }
}

func handleCSR(args: [String]) throws {
    var commonName = "AltSign"
    var org = "AltSign"
    var country = "US"
    var state = "CA"
    var locality = "Los Angeles"
    var outCSR: String?
    var outKey: String?

    var idx = 0
    while idx < args.count {
        let a = args[idx]
        if a == "--name" || a == "-n" { if idx + 1 < args.count { commonName = args[idx + 1]; idx += 1 } }
        else if a == "--org" || a == "-o" { if idx + 1 < args.count { org = args[idx + 1]; idx += 1 } }
        else if a == "--country" || a == "-c" { if idx + 1 < args.count { country = args[idx + 1]; idx += 1 } }
        else if a == "--state" { if idx + 1 < args.count { state = args[idx + 1]; idx += 1 } }
        else if a == "--locality" { if idx + 1 < args.count { locality = args[idx + 1]; idx += 1 } }
        else if a == "--output-csr" { if idx + 1 < args.count { outCSR = args[idx + 1]; idx += 1 } }
        else if a == "--output-key" { if idx + 1 < args.count { outKey = args[idx + 1]; idx += 1 } }
        idx += 1
    }

    guard let csrPath = outCSR, let keyPath = outKey else {
        print("""
        Usage:
          sidesign csr create [--name <commonName>] [--org <org>] --output-csr <request.csr> --output-key <private.key>
        """)
        exit(1)
    }

    let subject = CodeSignKit.CSRSubject(
        country: country,
        state: state,
        locality: locality,
        organization: org,
        commonName: commonName
    )

    let result = try CodeSignKit.CSRBuilder.generate(subject: subject)
    try result.csrPEM.data(using: .utf8)?.write(to: URL(fileURLWithPath: csrPath))
    try result.privateKeyPEM.data(using: .utf8)?.write(to: URL(fileURLWithPath: keyPath))
    print("Successfully generated CSR at \(csrPath) and Private Key at \(keyPath)")
}

func selectAnisetteServerInteractively(sourceURLString: String? = nil) async throws -> String {
    guard let sourceStr = sourceURLString, let url = URL(string: sourceStr) else {
        print("Error: --source <url> (or --list <url>) is required for interactive server selection.")
        exit(1)
    }

    print("Fetching available Anisette servers from \(url.host ?? url.absoluteString)...")
    let provider = AnisetteDataProvider.shared
    let data = try await provider.fetchServerList(from: url)

    let visibleServers = data.servers.filter { !$0.isHidden }
    guard !visibleServers.isEmpty else {
        print("No servers found in server list.")
        exit(1)
    }

    print("\nAvailable Anisette Servers:")
    for (index, s) in visibleServers.enumerated() {
        let label = s.name.isEmpty ? s.address : "\(s.name) (\(s.address))"
        print("  [\(index + 1)] \(label)")
    }

    print("\nSelect a server [1-\(visibleServers.count)]: ", terminator: "")
    guard let input = readLine(strippingNewline: true),
          let choice = Int(input),
          choice >= 1 && choice <= visibleServers.count else {
        print("Invalid selection.")
        exit(1)
    }

    let selected = visibleServers[choice - 1].address
    print("Selected: \(selected)\n")
    return selected
}

func handleAnisette(args: [String]) async throws {
    if args.first == "servers" || args.first == "list" {
        var sourceURLStr: String?
        var idx = 1
        while idx < args.count {
            let a = args[idx]
            if (a == "--source" || a == "--list" || a == "--url") && idx + 1 < args.count {
                sourceURLStr = args[idx + 1]
                idx += 1
            } else if a.hasPrefix("http://") || a.hasPrefix("https://") {
                sourceURLStr = a
            }
            idx += 1
        }

        guard let src = sourceURLStr, let url = URL(string: src) else {
            print("Error: Server list URL is required. Usage: sidesign anisette servers --source <url>")
            exit(1)
        }

        print("Fetching Anisette servers from \(url.absoluteString)...")
        let provider = AnisetteDataProvider.shared
        let data = try await provider.fetchServerList(from: url)

        print("\nAnisette Servers (\(data.servers.count)):")
        for s in data.servers {
            let visibility = s.isHidden ? " [Hidden]" : ""
            print("  * \(s.name.isEmpty ? "Server" : s.name): \(s.address)\(visibility)")
        }
        return
    }

    var serverURL: String?
    var localDir: String?
    var odaURL: String?
    var sourceURLStr: String?
    var anisetteDeviceUDID: String?
    var selectServer = false
    var asJSON = false
    var strict = false

    var idx = 0
    while idx < args.count {
        let a = args[idx]
        if a == "--json" { asJSON = true }
        else if a == "--strict" { strict = true }
        else if (a == "--local" || a == "--local-adi") && idx + 1 < args.count {
            localDir = args[idx + 1]
            idx += 1
        } else if a == "--oda" && idx + 1 < args.count {
            odaURL = args[idx + 1]
            idx += 1
        } else if (a == "--server" || a == "--url") && idx + 1 < args.count {
            serverURL = args[idx + 1]
            idx += 1
        } else if (a == "--source" || a == "--list") && idx + 1 < args.count {
            sourceURLStr = args[idx + 1]
            idx += 1
        } else if (a == "--anisette-device-udid" || a == "--anisette-udid") && idx + 1 < args.count {
            anisetteDeviceUDID = args[idx + 1]
            idx += 1
        } else if a == "--select-server" || a == "-s" {
            selectServer = true
        } else if a.hasPrefix("http://") || a.hasPrefix("https://") {
            serverURL = a
        }
        idx += 1
    }

    if selectServer {
        serverURL = try await selectAnisetteServerInteractively(sourceURLString: sourceURLStr)
    }

    let mode: AnisetteMode
    if let dir = localDir {
        mode = .localODA(libsDir: URL(fileURLWithPath: dir))
    } else if let odaStr = odaURL, let odaURL = URL(string: odaStr) {
        mode = .remoteODA(sourceURL: odaURL)
    } else if let sUrl = serverURL, let url = URL(string: sUrl) {
        if strict {
            let isValid = await AnisetteDataProvider.validateServer(url: url, strict: true)
            guard isValid else {
                print("Error: Strict validation failed for remote server '\(url.absoluteString)'. Endpoint is not ready or not returning valid Anisette payload.")
                exit(1)
            }
        }
        mode = .remote(server: url)
    } else {
        print("Error: An Anisette mode is required. Specify one of:")
        print("  --server <url>                 (Direct remote Anisette server)")
        print("  --local <dir>                  (Local ADI library directory)")
        print("  --oda <url>                    (Remote ODA package / catalog URL)")
        print("  --select-server --source <url> (Select interactively from catalog)")
        exit(1)
    }

    print("Fetching Anisette data...")
    let provider = AnisetteDataProvider(mode: mode)
    let identifier = (anisetteDeviceUDID != nil ? UUID(uuidString: anisetteDeviceUDID!) : nil) ?? UUID()
    let (data, _) = try await provider.fetchAnisetteData(identifier: identifier, customDeviceID: anisetteDeviceUDID)

    if asJSON {
        let headers = AnisetteDataProvider.toHTTPHeaders(data: data)
        if let jsonData = try? JSONSerialization.data(withJSONObject: headers, options: .prettyPrinted),
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

// Top-level entry execution
let args = Array(CommandLine.arguments.dropFirst())

if args.isEmpty || args.contains("-h") || args.contains("--help") || args.contains("help") {
    printUsage()
    exit(0)
}

if args.contains("--verbose") || args.contains("-v") || args.contains("-vv") || args.contains("--debug") {
    SideSignLogging.setLogging(true)
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
    case "p12":
        try handleP12(args: subArgs)
    case "csr":
        try handleCSR(args: subArgs)
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
