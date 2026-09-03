//
//  CommandHandler.swift
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

public enum CommandHandler {

    public static func printError(_ message: String) {
        FileHandle.standardError.write(Data("Error: \(message)\n".utf8))
    }

    public static func printWarning(_ message: String) {
        FileHandle.standardError.write(Data("Warning: \(message)\n".utf8))
    }

    public static func readInteractiveLine(prompt: String, emptyLineBefore: Bool = true, emptyLineAfter: Bool = true) -> String? {
        if emptyLineBefore { print() }
        print(prompt, terminator: "")
        fflush(nil)
        let line = readLine(strippingNewline: true)
        if emptyLineAfter { print() }
        return line
    }

    public static func readSecurePassword(prompt: String, emptyLineBefore: Bool = true, emptyLineAfter: Bool = true) -> String? {
        return SecureInput.readPassword(prompt: prompt, emptyLineBefore: emptyLineBefore, emptyLineAfter: emptyLineAfter)
    }

    public static func resolveTeamIDFromIndex(_ indexStr: String?) throws -> String {
        let sessions = SessionManager.listSessions().filter { $0.teamID != nil }
        guard !sessions.isEmpty else {
            throw CLIError.executionFailed("No saved team sessions found in '\(SessionManager.defaultSessionDirectory.path)'. Run 'sidesign dev login' first.")
        }

        let targetIndex: Int
        if let str = indexStr, let val = Int(str) {
            targetIndex = val
        } else {
            print("\nSaved Teams (\(sessions.count)):")
            for (idx, entry) in sessions.enumerated() {
                print("  \(idx + 1). Team: \(entry.teamID!)")
            }
            guard let entered = readInteractiveLine(prompt: "Select team (1-\(sessions.count)): "),
                  let parsed = Int(entered) else {
                throw CLIError.invalidArgument("Invalid team selection.")
            }
            targetIndex = parsed
        }

        guard targetIndex >= 1 && targetIndex <= sessions.count else {
            throw CLIError.invalidArgument("Invalid team index \(targetIndex). Available range: 1...\(sessions.count). Run 'sidesign dev list'.")
        }
        return sessions[targetIndex - 1].teamID!
    }

    public static func validateAndResolveTeamID(_ teamID: String) throws -> String {
        let targetURL = SessionManager.url(for: teamID)
        guard FileManager.default.fileExists(atPath: targetURL.path) else {
            let available = SessionManager.listSessions().compactMap { $0.teamID }
            let listStr = available.isEmpty ? "none" : available.joined(separator: ", ")
            throw CLIError.executionFailed("No saved session found for Team ID '\(teamID)'. Available teams: [\(listStr)]. Run 'sidesign dev list'.")
        }
        return teamID
    }

    public static func handleSign(context: SignContext) async throws {
        let targetURL = URL(fileURLWithPath: context.targetPath)
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: targetURL.path, isDirectory: &isDir) else {
            throw CLIError.executionFailed("Target path does not exist: \(context.targetPath)")
        }

        let p12URL = URL(fileURLWithPath: context.p12Path)
        guard FileManager.default.fileExists(atPath: p12URL.path) else {
            throw CLIError.executionFailed("P12 file does not exist: \(context.p12Path)")
        }

        let p12Data = try Data(contentsOf: p12URL)
        let keyStore = try KeyStore(p12Data: p12Data, password: context.password)

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
            if let profilePath = context.profilePath {
                let profURL = URL(fileURLWithPath: profilePath)
                let profData = try Data(contentsOf: profURL)
                if let profile = ProvisioningProfile(data: profData) {
                    profiles.append(profile)
                } else {
                    throw CLIError.executionFailed("Could not parse provisioning profile at \(profilePath)")
                }
            }

            let effectiveTeamID = context.teamID ?? profiles.first?.teamIdentifier ?? keyStore.certificate.organizationalUnit ?? "UNKNOWN"
            let team = Team(identifier: effectiveTeamID, name: keyStore.certificate.name, type: .free)

            print("[Sign] Signing App Bundle: \(appURL.lastPathComponent)")
            let signer = AppBundleSigner(team: team, keyStore: keyStore)
            try await signer.signApp(at: appURL, provisioningProfiles: profiles)

            if isIPA {
                print("[Package] Repackaging IPA...")
                let finalOutURL: URL
                if let outputPath = context.outputPath {
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
                if let outputPath = context.outputPath {
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
            if let entPath = context.entitlementsPath {
                entitlementsXML = try String(contentsOfFile: entPath, encoding: .utf8)
            }

            if isDir.boolValue {
                try CodeSignKit.CodeSigner.sign(
                    appPath: targetURL.path,
                    keyData: p12Data,
                    password: context.password,
                    teamID: context.teamID,
                    entitlementProvider: { _ in entitlementsXML ?? "" },
                    progress: {}
                )
                print("\(context.targetPath): signed bundle successfully")
            } else {
                let binaryData = try Data(contentsOf: targetURL)
                let cmsSigner = CodeSignKit.CMSSigner(p12Data: p12Data, password: context.password)
                let finalBundleID = context.bundleID ?? targetURL.lastPathComponent

                let signer = CodeSignKit.MachOSigner(
                    binaryData: binaryData,
                    bundleIdentifier: finalBundleID,
                    teamIdentifier: context.teamID,
                    entitlementsXML: entitlementsXML,
                    infoPlistData: nil,
                    codeResourcesData: nil,
                    cmsSigner: cmsSigner,
                    isMainExecutable: true
                )
                let signed = try signer.sign()
                try signed.write(to: targetURL, options: .atomic)
                print("\(context.targetPath): signed Mach-O binary successfully")
            }
        }
    }

    public static func handleVerify(context: VerifyContext) throws {
        let targetURL = URL(fileURLWithPath: context.targetPath)
        let isIPA = targetURL.pathExtension.lowercased() == "ipa"

        print("[Verify] Verifying signature for: \(targetURL.path)")

        let appURL: URL
        let workingDir: URL?
        if isIPA {
            let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
            try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
            workingDir = tempDir
            appURL = try FileManager.default.unzipAppBundle(at: targetURL, to: tempDir)
        } else {
            workingDir = nil
            appURL = targetURL
        }
        defer {
            if let dir = workingDir { try? FileManager.default.removeItem(at: dir) }
        }

        let result = CodeSignKit.SignatureVerifier.verify(url: appURL, deep: context.isDeep, strict: context.isStrict)
        if result.isValid {
            print("Signature is VALID.")
            if let ident = result.bundleIdentifier { print("Identifier=\(ident)") }
            if let team = result.teamIdentifier { print("TeamIdentifier=\(team)") }
            if let cdHash = result.cdHash { print("CDHash=\(cdHash)") }
        } else {
            let errorMsg = result.errors.joined(separator: "\n  - ")
            throw CLIError.executionFailed("Signature is INVALID.\n  - \(errorMsg)")
        }
    }

    public static func handleDisplay(context: InspectContext) throws {
        let targetURL = URL(fileURLWithPath: context.targetPath)
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
                throw CLIError.executionFailed("Unable to parse AppBundle at \(appURL.path)")
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
                if context.dumpEntitlements {
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
                    throw CLIError.executionFailed("Could not find executable inside bundle \(context.targetPath)")
                }
                execURL = exec
            } else {
                execURL = targetURL
            }

            guard let parser = try? CodeSignKit.MachOParser(url: execURL) else {
                throw CLIError.executionFailed("Failed to parse Mach-O binary at \(execURL.path)")
            }

            if context.dumpEntitlements {
                if let xml = try? parser.entitlements() {
                    print(xml)
                } else {
                    print("No XML entitlements found in binary.")
                }
            } else if context.dumpRequirements {
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

    public static func handleProfile(context: ProfileContext) throws {
        let fileURL = URL(fileURLWithPath: context.profilePath)
        let data = try Data(contentsOf: fileURL)
        guard let profile = ProvisioningProfile(data: data) else {
            throw CLIError.executionFailed("Could not parse provisioning profile at \(context.profilePath)")
        }

        switch context.action {
        case .dump:
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

        case .validate:
            let isExpired = profile.expirationDate < Date()
            if isExpired {
                throw CLIError.executionFailed("Profile is EXPIRED on \(profile.expirationDate).")
            } else {
                print("Profile is VALID (expires on \(profile.expirationDate)).")
            }
        }
    }

    public static func handleExtensions(context: ExtensionsContext) throws {
        let targetURL = URL(fileURLWithPath: context.targetPath)
        let isIPA = targetURL.pathExtension.lowercased() == "ipa"

        let workingDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: workingDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: workingDir) }

        let appURL = isIPA ? try FileManager.default.unzipAppBundle(at: targetURL, to: workingDir) : targetURL
        guard let app = AppBundle(fileURL: appURL) else {
            throw CLIError.executionFailed("Failed to parse AppBundle at \(appURL.path)")
        }

        switch context.action {
        case .list:
            print("App Extensions in \(app.name): (\(app.appExtensions.count))")
            for ext in app.appExtensions {
                print("  * \(ext.name) [\(ext.bundleIdentifier)]")
            }

        case .remove(let removeAll, let targetID, let outputPath):
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
        }
    }

    public static func handleArchive(context: ArchiveContext) throws {
        switch context.action {
        case .unzip(let inputPath, let outputPath):
            let inputURL = URL(fileURLWithPath: inputPath)
            let destDir = outputPath.map { URL(fileURLWithPath: $0) } ?? inputURL.deletingLastPathComponent()
            print("[Unpack] Unpacking \(inputURL.lastPathComponent) to \(destDir.path)...")
            let appURL = try FileManager.default.unzipAppBundle(at: inputURL, to: destDir)
            print("Extracted app bundle: \(appURL.path)")

        case .zip(let inputPath, let outputPath):
            let inputURL = URL(fileURLWithPath: inputPath)
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
        }
    }

    public static func handleRemoveSignature(context: RemoveSignatureContext) throws {
        let targetURL = URL(fileURLWithPath: context.targetPath)
        print("[Remove] Removing code signature from: \(targetURL.path)")
        try CodeSignKit.CodeSigner.removeSignature(at: targetURL)
        print("Successfully removed code signature.")
    }

    public static func handleP12(context: P12Context) throws {
        switch context.action {
        case .create(let certPath, let keyPath, let password, let outputPath):
            let certData = try Data(contentsOf: URL(fileURLWithPath: certPath))
            let keyData = try Data(contentsOf: URL(fileURLWithPath: keyPath))
            let p12Data = try PKCS12Parser.create(cert: certData, key: keyData, password: password)
            try p12Data.write(to: URL(fileURLWithPath: outputPath))
            print("Successfully created PKCS#12 bundle at: \(outputPath)")

        case .extract(let inputPath, let password, let outCertPath, let outKeyPath):
            let p12Data = try Data(contentsOf: URL(fileURLWithPath: inputPath))
            let result = try PKCS12Parser.extract(p12Data, password: password)
            try result.cert.write(to: URL(fileURLWithPath: outCertPath))
            try result.key.write(to: URL(fileURLWithPath: outKeyPath))
            print("Successfully extracted certificate to \(outCertPath) and private key to \(outKeyPath)")
        }
    }

    public static func handleCSR(context: CSRContext) throws {
        let subject = CodeSignKit.CSRSubject(
            country: context.country,
            state: context.state,
            locality: context.locality,
            organization: context.organization,
            commonName: context.commonName
        )

        let result = try CodeSignKit.CSRBuilder.generate(subject: subject)
        try result.csrPEM.data(using: .utf8)?.write(to: URL(fileURLWithPath: context.outputCSR))
        try result.privateKeyPEM.data(using: .utf8)?.write(to: URL(fileURLWithPath: context.outputKey))
        print("Successfully generated CSR at \(context.outputCSR) and Private Key at \(context.outputKey)")
    }

    public static func handleAnisette(context: AnisetteContext) async throws {
        switch context.action {
        case .listServers(let sourceURL):
            guard let url = URL(string: sourceURL) else {
                throw CLIError.invalidArgument("Invalid server list URL: \(sourceURL)")
            }
            print("Fetching Anisette servers from \(url.absoluteString)...")
            let provider = AnisetteDataProvider.shared
            let data = try await provider.fetchServerList(from: url)

            print("\nAnisette Servers (\(data.servers.count)):")
            for s in data.servers {
                let visibility = s.isHidden ? " [Hidden]" : ""
                print("  * \(s.name.isEmpty ? "Server" : s.name): \(s.address)\(visibility)")
            }

        case .generate(
            var serverURL,
            let localDir,
            let odaURL,
            let sourceURLStr,
            let anisetteDeviceUDID,
            let deviceDataPath,
            var deviceDataPassword,
            let teamID,
            let selectServer,
            let enableFailover,
            let startIndex,
            let asJSON,
            let strict,
            let forceODA
        ):
            if selectServer {
                serverURL = try await selectAnisetteServerInteractively(sourceURLString: sourceURLStr)
            }

            var failoverURLs: [URL] = []
            let mode: AnisetteMode
            if enableFailover {
                guard let sourceStr = sourceURLStr, let listURL = URL(string: sourceStr) else {
                    throw CLIError.missingRequiredArgument("--source <url> is required when using --failover.")
                }
                let serverData = try await AnisetteDataProvider.shared.fetchServerList(from: listURL)
                let visible = serverData.servers.filter { !$0.isHidden }
                failoverURLs = visible.compactMap { URL(string: $0.address) }
                guard !failoverURLs.isEmpty else {
                    throw CLIError.executionFailed("No active servers found in catalog '\(listURL.absoluteString)'.")
                }
                mode = .remote(server: failoverURLs.first!)
            } else if let dir = localDir {
                mode = .localODA(libsDir: URL(fileURLWithPath: dir))
            } else if let odaStr = odaURL, let oURL = URL(string: odaStr) {
                try await AnisetteDataProvider.shared.setupFromRemote(serverSourceURL: oURL, force: forceODA)
                mode = .localODA(libsDir: AnisetteDataProvider.shared.remoteLibsDir)
            } else if let sUrl = serverURL, let url = URL(string: sUrl) {
                if strict {
                    let isValid = await AnisetteDataProvider.validateServer(url: url, strict: true)
                    guard isValid else {
                        throw CLIError.executionFailed("Strict validation failed for remote server '\(url.absoluteString)'. Endpoint is not ready or not returning valid Anisette payload.")
                    }
                }
                mode = .remote(server: url)
            } else if LocalAnisetteProvider.validateLibrariesExist(at: AnisetteDataProvider.shared.libsDir) {
                mode = .localODA(libsDir: AnisetteDataProvider.shared.libsDir)
            } else {
                throw CLIError.missingRequiredArgument("""
                An Anisette mode is required. Specify one of:
                  --server <url>                 (Direct remote Anisette server)
                  --local <dir>                  (Local ADI library directory)
                  --oda <url>                    (Remote ODA package / catalog URL)
                  --select-server --source <url> (Select interactively from catalog)
                  --failover --source <url>      (Automatic catalog failover)
                """)
            }

            var existingData: DeviceData? = nil
            let targetDataURL = deviceDataPath.map { URL(fileURLWithPath: $0) } ?? DeviceDataManager.url(for: teamID)

            if DeviceDataManager.hasData(at: targetDataURL) {
                var devPass = deviceDataPassword
                var loaded = false
                while !loaded {
                    if let p = devPass {
                        do {
                            existingData = try DeviceDataManager.load(from: targetDataURL, password: p)
                            deviceDataPassword = p
                            loaded = true
                        } catch DeviceDataError.invalidPassword {
                            printError("Invalid device data password.")
                            guard let entered = readSecurePassword(prompt: "Enter password for device data ('\(targetDataURL.lastPathComponent)'): "), !entered.isEmpty else {
                                throw CLIError.executionFailed("Operation cancelled.")
                            }
                            devPass = entered
                        } catch {
                            throw CLIError.executionFailed("Loading device data from '\(targetDataURL.path)': \(error.localizedDescription)")
                        }
                    } else {
                        guard let entered = readSecurePassword(prompt: "Enter password for device data ('\(targetDataURL.lastPathComponent)'): "), !entered.isEmpty else {
                            throw CLIError.missingRequiredArgument("Device data password cannot be empty.")
                        }
                        devPass = entered
                    }
                }
            }

            if !asJSON {
                switch mode {
                case .remote(let server):
                    if !enableFailover {
                        print("Fetching Anisette data from \(server.absoluteString)...")
                    }
                case .localODA(let dir, _):
                    print("Generating Anisette data using local ADI libraries (\(dir.path))...")
                case .remoteODA(let src, _):
                    print("Fetching On-Device Anisette package from \(src.absoluteString)...")
                }
                if enableFailover {
                    print("Fetching Anisette data with auto-failover across \(failoverURLs.count) servers (start index: \(startIndex))...")
                }
                print()
            }

            let provider = AnisetteDataProvider(mode: mode)
            let identifier = existingData?.identifier ?? (anisetteDeviceUDID != nil ? UUID(uuidString: anisetteDeviceUDID!) : nil) ?? UUID()
            let data: AnisetteData
            let newAdiPb: Data?

            let outputJSON = asJSON

            let errorHandler: @Sendable (Error) async throws -> Bool = { error in
                if case AnisetteError.outdatedV1Server(let serverURL, let reason) = error {
                    if !outputJSON {
                        print()
                        if let reason = reason, !reason.isEmpty {
                            printWarning("V3 Anisette is unavailable on '\(serverURL.absoluteString)' (\(reason)).")
                        } else {
                            printWarning("V3 Anisette is unavailable on '\(serverURL.absoluteString)'.")
                        }
                        printWarning("Falling back to legacy V1 mode uses a shared device identity and may increase the risk of Apple ID lockouts.")
                        let input = readInteractiveLine(prompt: "Do you want to continue with legacy V1 Anisette? [Y/n]: ", emptyLineBefore: false, emptyLineAfter: true)?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? ""
                        if input == "n" || input == "no" {
                            return false
                        }
                        return true
                    } else {
                        return true
                    }
                }
                return false
            }

            if enableFailover {
                let res = try await provider.fetchAnisetteDataWithFailover(
                    servers: failoverURLs,
                    startIndex: startIndex,
                    identifier: identifier,
                    existingAdiBlob: existingData?.adiBlob,
                    customDeviceID: anisetteDeviceUDID,
                    onError: errorHandler,
                    onSuccess: { @Sendable winURL in
                        if !outputJSON {
                            print("Connected to Anisette server: \(winURL.absoluteString)")
                        }
                    }
                )
                data = res.data
                newAdiPb = res.newAdiBlob
            } else {
                let res = try await provider.fetchAnisetteData(
                    identifier: identifier,
                    existingAdiBlob: existingData?.adiBlob,
                    customDeviceID: anisetteDeviceUDID,
                    onError: errorHandler
                )
                data = res.data
                newAdiPb = res.newAdiBlob
                if !outputJSON {
                    print("Anisette headers acquired successfully.")
                }
            }

            if let freshBlob = newAdiPb {
                if deviceDataPassword == nil {
                    if let entered = readSecurePassword(prompt: "Enter password to encrypt new device data (\(targetDataURL.lastPathComponent)): "), !entered.isEmpty {
                        deviceDataPassword = entered
                    }
                }
                if let devPass = deviceDataPassword {
                    let newData = DeviceData(
                        identifier: identifier,
                        adiBlob: freshBlob,
                        machineID: data.machineID,
                        localUserID: data.localUserID
                    )
                    try DeviceDataManager.save(newData, to: targetDataURL, password: devPass)
                    print("Device data saved and encrypted to: \(targetDataURL.path)")
                }
            }

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
    }

    public static func handlePortal(request: PortalRequestContext) async throws {
        switch request {
        case .list:
            handleAuthList()
        case .selectTeam(let index):
            try handleAuthSelectTeam(index: index)
        case .selectTeamID(let teamID):
            try handleAuthSelectTeamID(teamID: teamID)
        case .logout(let sessionPath, let teamID, let clearMachine):
            try handleAuthLogout(sessionPath: sessionPath, teamID: teamID, clearMachine: clearMachine)
        case .status(let sessionPath, let password, let encryptPassword, let teamID):
            try handleAuthStatus(sessionPath: sessionPath, password: password, encryptPassword: encryptPassword, teamID: teamID)
        case .relogin(let options):
            try await handleAuthRelogin(options: options)
        case .login(let options):
            try await handleAuthLogin(options: options)
        case .teams(let options):
            try await handleAuthTeams(options: options)
        case .devices(let options):
            try await handleAuthDevices(options: options)
        case .authDevices(let options):
            try await handleAuthDevicesOperations(options: options)
        case .certs(let options):
            try await handleAuthCerts(options: options)
        case .appIDs(let options):
            try await handleAuthAppIDs(options: options)
        case .appGroups(let options):
            try await handleAuthAppGroups(options: options)
        case .profiles(let options):
            try await handleAuthProfiles(options: options)
        }
    }

    public static func handleAuth(request: PortalRequestContext) async throws {
        try await handlePortal(request: request)
    }

    private static func handleAuthList() {
        let teamSessions = SessionManager.listSessions().filter { $0.teamID != nil }
        if teamSessions.isEmpty {
            if SessionManager.hasSession(at: SessionManager.defaultSessionURL) {
                print("Default session found at: \(SessionManager.defaultSessionURL.path)")
            } else {
                print("No saved sessions found in: \(SessionManager.defaultSessionDirectory.path)")
            }
            return
        }

        let defaultData = try? Data(contentsOf: SessionManager.defaultSessionURL)
        print("Saved Teams (\(teamSessions.count)):")
        for (idx, entry) in teamSessions.enumerated() {
            let teamData = try? Data(contentsOf: entry.url)
            let isActive = (defaultData != nil && teamData != nil && defaultData == teamData)
            let badge = isActive ? " [Active]" : ""
            print("  \(idx + 1). \(entry.teamID!) (\(entry.url.lastPathComponent))\(badge)")
        }
    }

    private static func handleAuthSelectTeam(index: String?) throws {
        let targetID = try resolveTeamIDFromIndex(index)
        try SessionManager.setActiveSession(forTeamID: targetID)
        print("Active team set to: \(targetID)")
        print("Updated default session: \(SessionManager.defaultSessionURL.path)")
    }

    private static func handleAuthSelectTeamID(teamID: String) throws {
        let targetID = try validateAndResolveTeamID(teamID)
        try SessionManager.setActiveSession(forTeamID: targetID)
        print("Active team set to: \(targetID)")
        print("Updated default session: \(SessionManager.defaultSessionURL.path)")
    }

    private static func handleAuthLogout(sessionPath: String?, teamID: String?, clearMachine: Bool) throws {
        let sessionURL = sessionPath.map { URL(fileURLWithPath: $0) } ?? SessionManager.url(for: teamID)
        try SessionManager.clear(at: sessionURL)
        print("Logged out. Session cleared at \(sessionURL.path).")
        if clearMachine {
            try DeviceDataManager.clear(at: nil)
            print("Local device data (machine.dat) cleared.")
        }
    }

    private static func handleAuthStatus(sessionPath: String?, password: String?, encryptPassword: String?, teamID: String?) throws {
        let sessionURL = sessionPath.map { URL(fileURLWithPath: $0) } ?? SessionManager.url(for: teamID)
        guard SessionManager.hasSession(at: sessionURL) else {
            throw CLIError.executionFailed("No active session found at '\(sessionURL.path)'. Please run: sidesign dev login --apple-id <apple-id>")
        }
        let authSession: AuthSession
        do {
            authSession = try SessionManager.load(from: sessionURL, password: password ?? encryptPassword)
        } catch SessionStorageError.invalidPassword {
            guard let entered = readSecurePassword(prompt: "Enter session decryption password: "), !entered.isEmpty else {
                throw CLIError.missingRequiredArgument("Password required to decrypt session.")
            }
            authSession = try SessionManager.load(from: sessionURL, password: entered)
        }
        print("Active Session:")
        print("  Account Name: \(authSession.account.name)")
        print("  Account DSID: \(authSession.account.identifier)")
        print("  Session Path: \(sessionURL.path)")
    }

    private static func handleAuthRelogin(options: PortalOptions) async throws {
        let sessionURL = options.sessionPath.map { URL(fileURLWithPath: $0) } ?? SessionManager.url(for: options.teamID)
        guard SessionManager.hasSession(at: sessionURL) else {
            throw CLIError.executionFailed("No active session found at '\(sessionURL.path)' to relogin. Please run: sidesign dev login --apple-id <apple-id>")
        }
        let email: String
        do {
            let existingSession = try SessionManager.load(from: sessionURL, password: options.password ?? options.encryptPassword)
            email = existingSession.account.appleID
        } catch SessionStorageError.invalidPassword {
            guard let entered = readSecurePassword(prompt: "Enter session decryption password: "), !entered.isEmpty else {
                throw CLIError.missingRequiredArgument("Password required to decrypt session.")
            }
            let existingSession = try SessionManager.load(from: sessionURL, password: entered)
            email = existingSession.account.appleID
        }
        print("Re-authenticating account: \(email)")

        try await performLogin(
            appleID: email,
            password: options.password,
            sessionURL: sessionURL,
            options: options
        )
    }

    private static func handleAuthLogin(options: PortalLoginOptions) async throws {
        let sessionURL = options.portalOptions.sessionPath.map { URL(fileURLWithPath: $0) } ?? SessionManager.url(for: options.portalOptions.teamID)
        try await performLogin(
            appleID: options.appleID,
            password: options.portalOptions.password,
            sessionURL: sessionURL,
            options: options.portalOptions
        )
    }

    private static func handleAuthTeams(options: PortalOptions) async throws {
        try await executePortalOperation(options: options) { portal, account, session in
            let teams = try await portal.fetchTeams(for: account, session: session)
            if !SideSignLogging.isLoggingEnabled {
                print("\nDeveloper Teams:")
                for t in teams {
                    print("  * \(t.name) (ID: \(t.identifier), Type: \(t.type.rawValue))")
                }
            }
        }
    }

    private static func handleAuthDevices(options: PortalDeviceOptions) async throws {
        try await executePortalOperation(options: options.portalOptions) { portal, account, session in
            let teams = try await portal.fetchTeams(for: account, session: session)
            guard let team = teams.first else {
                printError("No teams found on this account.")
                return
            }

            switch options.action {
            case .register(let name, let udid):
                print("Registering device '\(name)' (\(udid))...")
                let newDevice = try await portal.registerDevice(name: name, identifier: udid, type: .all, team: team, session: session)
                print("Successfully registered device: \(newDevice.name) (UDID: \(newDevice.identifier))")

            case .update(let name, let udid):
                let devices = try await portal.fetchDevices(for: team, session: session)
                guard var targetDevice = devices.first(where: { $0.identifier == udid || $0.deviceID == udid }) else {
                    throw CLIError.executionFailed("Device '\(udid)' not found.")
                }
                targetDevice.name = name
                print("Updating device name to '\(name)'...")
                let updated = try await portal.updateDevice(targetDevice, team: team, session: session)
                print("Successfully updated device: \(updated.name) (\(updated.identifier))")

            case .disable(let udid):
                let devices = try await portal.fetchDevices(for: team, session: session)
                guard let targetDevice = devices.first(where: { $0.identifier == udid || $0.deviceID == udid }) else {
                    throw CLIError.executionFailed("Device '\(udid)' not found.")
                }
                print("Disabling device '\(targetDevice.name)' (\(udid))...")
                let disabled = try await portal.disableDevice(targetDevice, team: team, session: session)
                print("Device disabled: \(disabled.name) (\(disabled.identifier))")

            case .delete(let udid):
                let devices = try await portal.fetchDevices(for: team, session: session)
                guard let targetDevice = devices.first(where: { $0.identifier == udid || $0.deviceID == udid }) else {
                    throw CLIError.executionFailed("Device '\(udid)' not found.")
                }
                print("Deleting device '\(targetDevice.name)' (\(udid))...")
                _ = try await portal.deleteDevice(targetDevice, team: team, session: session)
                print("Device deleted successfully.")

            case .list:
                let devices = try await portal.fetchDevices(for: team, session: session)
                if !SideSignLogging.isLoggingEnabled {
                    print("Devices for Team \(team.name) (\(devices.count)):")
                    for d in devices {
                        let devIDStr = d.deviceID != nil ? " [DeviceID: \(d.deviceID!)]" : ""
                        print("  - \(d.name) (UDID: \(d.identifier))\(devIDStr)")
                    }
                }
            }
        }
    }

    private static func handleAuthDevicesOperations(options: PortalAuthDeviceOptions) async throws {
        try await executePortalOperation(options: options.portalOptions) { portal, _, session in

            switch options.action {
            case .list:
                print("Fetching auth devices...")
                let devices = try await portal.fetchAuthDevices(session: session)
                if devices.isEmpty {
                    print("No auth devices found or device list is empty.")
                    return
                }
                print("\nAuth Devices (\(devices.count)):")
                for (idx, d) in devices.enumerated() {
                    let currentMarker = d.isCurrentDevice ? " [This Device]" : ""
                    let modelStr = d.modelDisplayName ?? d.model ?? "Unknown Model"
                    let osStr = d.osVersion.map { " (OS: \($0))" } ?? ""
                    let serialStr = d.serialNumber.map { " [Serial: \($0)]" } ?? ""
                    print("  \(idx + 1). \(d.name) - \(modelStr)\(osStr)\(serialStr)")
                    print("     ID: \(d.id)\(currentMarker)")
                }
                print("")

            case .remove(let deviceID):
                print("Removing auth device '\(deviceID)' from account...")
                let success = try await portal.removeAuthDevice(id: deviceID, session: session)
                if success {
                    print("Successfully removed auth device '\(deviceID)' from account.")
                } else {
                    throw CLIError.executionFailed("Failed to remove auth device '\(deviceID)' from account.")
                }

            case .purgeAnisette:
                print("Scanning auth devices for simulated Anisette machines...")
                let devices = try await portal.fetchAuthDevices(session: session)
                let candidates = devices.filter { d in
                    if d.isCurrentDevice { return false }
                    let n = d.name.lowercased()
                    let m = (d.modelDisplayName ?? d.model ?? "").lowercased()
                    return n == "mac"   || n.hasPrefix("macbook") || 
                           n == "linux" || m.contains("mac")      || m.contains("linux")
                }

                if candidates.isEmpty {
                    print("No simulated Anisette devices found to purge.")
                    return
                }

                print("Found \(candidates.count) candidate device(s) to purge:")
                for c in candidates {
                    print("  - \(c.name) (ID: \(c.id))")
                }

                var removedCount = 0
                for c in candidates {
                    print("Removing '\(c.name)' (ID: \(c.id))...")
                    do {
                        if try await portal.removeAuthDevice(id: c.id, session: session) {
                            removedCount += 1
                        }
                    } catch {
                        printError("Failed to remove '\(c.name)': \(error.localizedDescription)")
                    }
                }
                print("Purged \(removedCount)/\(candidates.count) simulated device(s) from account.")
            }
        }
    }

    private static func handleAuthCerts(options: PortalCertOptions) async throws {
        try await executePortalOperation(options: options.portalOptions) { portal, account, session in
            let teams = try await portal.fetchTeams(for: account, session: session)
            guard let team = teams.first else {
                printError("No teams found on this account.")
                return
            }

            switch options.action {
            case .create(_, let outPath):
                print("Creating new Development Certificate from Apple...")
                let keyStore = try await portal.addCertificate(machineName: "Mac", to: team, session: session)
                if let out = outPath {
                    let outURL = URL(fileURLWithPath: out)
                    if outURL.pathExtension.lowercased() == "p12" {
                        let p12Password = options.portalOptions.password ?? keyStore.certificate.serialNumber
                        let p12Data = try keyStore.exportP12(password: p12Password)
                        try p12Data.write(to: outURL)
                        print("PKCS#12 identity saved to: \(outURL.path) (Password: \(p12Password))")
                    } else {
                        guard let certData = keyStore.certificate.data else {
                            throw CLIError.executionFailed("Certificate raw data is unavailable.")
                        }
                        try certData.write(to: outURL)
                        print("Certificate saved to: \(outURL.path)")
                    }
                } else {
                    print("Successfully created certificate: \(keyStore.certificate.name) (Serial: \(keyStore.certificate.serialNumber))")
                }

            case .revoke(let certID):
                print("Revoking certificate \(certID)...")
                let certs = try await portal.fetchCertificates(for: team, session: session)
                if let targetCert = certs.first(where: { $0.identifier == certID || $0.serialNumber == certID }) {
                    _ = try await portal.revokeCertificate(targetCert, for: team, session: session)
                    print("Certificate revoked successfully.")
                } else {
                    throw CLIError.executionFailed("Certificate ID not found.")
                }

            case .list:
                let certs = try await portal.fetchCertificates(for: team, session: session)
                if !SideSignLogging.isLoggingEnabled {
                    print("\nCertificates for team '\(team.name)':")
                    for c in certs {
                        print("  * \(c.name) [ID: \(c.identifier ?? "unknown"), Serial: \(c.serialNumber)]")
                    }
                }
            }
        }
    }

    private static func handleAuthAppIDs(options: PortalAppIDOptions) async throws {
        try await executePortalOperation(options: options.portalOptions) { portal, account, session in
            let teams = try await portal.fetchTeams(for: account, session: session)
            guard let team = teams.first else { return }

            switch options.action {
            case .register(let name, let bundleID):
                print("Registering App ID '\(name)' (\(bundleID))...")
                let appID = try await portal.addAppID(withName: name, bundleIdentifier: bundleID, team: team, session: session)
                print("Successfully created App ID: \(appID.name) (\(appID.bundleIdentifier), ID: \(appID.identifier))")

            case .delete(let targetID):
                let appIDs = try await portal.fetchAppIDs(for: team, session: session)
                if let target = appIDs.first(where: { $0.identifier == targetID || $0.bundleIdentifier == targetID }) {
                    _ = try await portal.deleteAppID(target, for: team, session: session)
                    print("Successfully deleted App ID: \(target.name) (\(target.bundleIdentifier))")
                } else {
                    throw CLIError.executionFailed("App ID '\(targetID)' not found.")
                }

            case .list:
                let appIDs = try await portal.fetchAppIDs(for: team, session: session)
                if !SideSignLogging.isLoggingEnabled {
                    print("\nApp IDs for team '\(team.name)':")
                    for a in appIDs {
                        print("  * \(a.name) [\(a.bundleIdentifier)] (ID: \(a.identifier))")
                    }
                }
            }
        }
    }

    private static func handleAuthAppGroups(options: PortalAppGroupOptions) async throws {
        try await executePortalOperation(options: options.portalOptions) { portal, account, session in
            let teams = try await portal.fetchTeams(for: account, session: session)
            guard let team = teams.first else { return }

            switch options.action {
            case .create(let name, let groupID):
                print("Creating App Group '\(name)' (\(groupID))...")
                let group = try await portal.addAppGroup(name: name, groupIdentifier: groupID, team: team, session: session)
                print("Successfully created App Group: \(group.name) (\(group.identifier))")

            case .assign(let appIDStr, let groupIDStr):
                let appIDs = try await portal.fetchAppIDs(for: team, session: session)
                guard let targetAppID = appIDs.first(where: { $0.identifier == appIDStr || $0.bundleIdentifier == appIDStr }) else {
                    throw CLIError.executionFailed("App ID '\(appIDStr)' not found.")
                }
                let groups = try await portal.fetchAppGroups(for: team, session: session)
                guard let targetGroup = groups.first(where: { $0.identifier == groupIDStr || $0.groupID == groupIDStr }) else {
                    throw CLIError.executionFailed("App Group '\(groupIDStr)' not found.")
                }
                let updated = try await portal.assignAppGroups([targetGroup], to: targetAppID, team: team, session: session)
                print("Successfully assigned group to App ID: \(updated.name)")

            case .update(let name, let groupIDStr):
                let groups = try await portal.fetchAppGroups(for: team, session: session)
                guard var targetGroup = groups.first(where: { $0.identifier == groupIDStr || $0.groupID == groupIDStr }) else {
                    throw CLIError.executionFailed("App Group '\(groupIDStr)' not found.")
                }
                targetGroup.name = name
                print("Updating App Group name to '\(name)'...")
                let updated = try await portal.updateAppGroup(targetGroup, team: team, session: session)
                print("Successfully updated App Group: \(updated.name) (\(updated.identifier))")

            case .delete(let groupIDStr):
                let groups = try await portal.fetchAppGroups(for: team, session: session)
                guard let targetGroup = groups.first(where: { $0.identifier == groupIDStr || $0.groupID == groupIDStr }) else {
                    throw CLIError.executionFailed("App Group '\(groupIDStr)' not found.")
                }
                print("Deleting App Group '\(targetGroup.name)' (\(targetGroup.identifier))...")
                _ = try await portal.deleteAppGroup(targetGroup, team: team, session: session)
                print("Successfully deleted App Group.")

            case .list:
                let groups = try await portal.fetchAppGroups(for: team, session: session)
                if !SideSignLogging.isLoggingEnabled {
                    print("\nApp Groups for team '\(team.name)':")
                    for g in groups {
                        print("  * \(g.name) [\(g.identifier)] (ID: \(g.groupID))")
                    }
                }
            }
        }
    }

    private static func handleAuthProfiles(options: PortalProfileOptions) async throws {
        try await executePortalOperation(options: options.portalOptions) { portal, account, session in
            let teams = try await portal.fetchTeams(for: account, session: session)
            guard let team = teams.first else { return }

            switch options.action {
            case .download(let bundleID, let outputPath):
                let appIDs = try await portal.fetchAppIDs(for: team, session: session)
                guard let targetAppID = appIDs.first(where: { $0.bundleIdentifier == bundleID || $0.identifier == bundleID }) else {
                    throw CLIError.executionFailed("App ID '\(bundleID)' not found.")
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

            case .delete(let profID):
                let profiles = try await portal.fetchProvisioningProfiles(for: team, session: session)
                if let target = profiles.first(where: { $0.identifier == profID || $0.uuid.uuidString == profID }) {
                    _ = try await portal.deleteProvisioningProfile(target, team: team, session: session)
                    print("Successfully deleted Provisioning Profile: \(target.name)")
                } else {
                    throw CLIError.executionFailed("Provisioning Profile '\(profID)' not found.")
                }

            case .list:
                let profiles = try await portal.fetchProvisioningProfiles(for: team, session: session)
                if !SideSignLogging.isLoggingEnabled {
                    print("\nProvisioning Profiles for team '\(team.name)':")
                    for p in profiles {
                        print("  * \(p.name) [\(p.bundleIdentifier)] (UUID: \(p.uuid))")
                    }
                }
            }
        }
    }

    private static func performLogin(
        appleID: String,
        password: String?,
        sessionURL: URL,
        options: PortalOptions
    ) async throws {
        let (anisetteData, _, _, _) = try await fetchAnisetteHeaders(options: options)

        let pwd: String
        if let p = password, !p.isEmpty {
            pwd = p
        } else {
            guard let entered = readSecurePassword(prompt: "Enter password for \(appleID): "), !entered.isEmpty else {
                throw CLIError.missingRequiredArgument("Password cannot be empty.")
            }
            pwd = entered
        }

        let portal = DeveloperPortal()
        print("Authenticating with Apple Developer Portal...")
        let authSession = try await portal.authenticate(
            appleID: appleID,
            password: pwd,
            anisetteData: anisetteData,
            xcodeVersion: "26.0",
            verificationHandler: handleCLI2FA
        )

        var discoveredTeamID: String?
        if options.teamID == nil {
            if let teams = try? await portal.fetchTeams(for: authSession.account, session: authSession.session),
               let firstTeam = teams.first {
                discoveredTeamID = firstTeam.identifier
                let teamURL = SessionManager.url(for: firstTeam.identifier)
                try SessionManager.save(authSession, to: teamURL, password: options.encryptPassword)
                print("Default team '\(firstTeam.name)' (\(firstTeam.identifier)) associated with session: \(teamURL.path)")
            }
        }

        if discoveredTeamID == nil {
            try SessionManager.save(authSession, to: sessionURL, password: options.encryptPassword)
            print("Authentication successful! Session saved to: \(sessionURL.path)")
        }

        let teamSuffix = discoveredTeamID != nil ? " (Team: \(discoveredTeamID!))" : ""
        print("Logged in as: \(authSession.account.name) (DSID: \(authSession.account.identifier)\(teamSuffix))")
    }

    private static func executePortalOperation(
        options: PortalOptions,
        operation: (DeveloperPortal, Account, Session) async throws -> Void
    ) async throws {
        let target = options.sessionPath.map { URL(fileURLWithPath: $0) } ?? SessionManager.url(for: options.teamID)
        guard SessionManager.hasSession(at: target) else {
            throw CLIError.executionFailed("No active session found at '\(target.path)'. Please run: sidesign dev login --apple-id <apple-id>")
        }

        let authSession: AuthSession
        do {
            authSession = try SessionManager.load(from: target, password: options.password ?? options.encryptPassword)
        } catch SessionStorageError.invalidPassword {
            guard let entered = readSecurePassword(prompt: "Enter session decryption password: "), !entered.isEmpty else {
                throw CLIError.missingRequiredArgument("Password required to decrypt session.")
            }
            authSession = try SessionManager.load(from: target, password: entered)
        }

        let (anisetteData, _, _, _) = try await fetchAnisetteHeaders(options: options)

        let account = authSession.account
        var session = authSession.session
        session.anisetteData = anisetteData
        let portal = DeveloperPortal()

        do {
            try await operation(portal, account, session)
        } catch {
            if case DeveloperPortalError.incorrectCredentials(let cause) = error {
                throw CLIError.executionFailed("Authentication session expired or credentials changed: \(cause ?? error.localizedDescription)\nPlease re-authenticate by running: sidesign dev relogin")
            } else if error.localizedDescription.contains("401") || error.localizedDescription.localizedCaseInsensitiveContains("unauthorized") || error.localizedDescription.localizedCaseInsensitiveContains("session") {
                throw CLIError.executionFailed("Developer portal session has expired or credentials have changed.\nPlease re-authenticate by running: sidesign dev relogin")
            }
            throw error
        }
    }

    private static func fetchAnisetteHeaders(options: PortalOptions) async throws -> (AnisetteData, Data?, URL, String?) {
        var serverURL = options.anisetteURL
        if options.selectServer {
            serverURL = try await selectAnisetteServerInteractively(sourceURLString: options.sourceURLStr)
        }

        var failoverURLs: [URL] = []
        let mode: AnisetteMode
        if options.enableFailover {
            guard let sourceStr = options.sourceURLStr, let listURL = URL(string: sourceStr) else {
                throw CLIError.missingRequiredArgument("--source <url> is required when using --failover.")
            }
            let serverData = try await AnisetteDataProvider.shared.fetchServerList(from: listURL)
            let visible = serverData.servers.filter { !$0.isHidden }
            failoverURLs = visible.compactMap { URL(string: $0.address) }
            guard !failoverURLs.isEmpty else {
                throw CLIError.executionFailed("No active servers found in catalog '\(listURL.absoluteString)'.")
            }
            mode = .remote(server: failoverURLs.first!)
        } else if let dir = options.localAnisetteDir {
            mode = .localODA(libsDir: URL(fileURLWithPath: dir))
        } else if let odaStr = options.odaURL, let oURL = URL(string: odaStr) {
            try await AnisetteDataProvider.shared.setupFromRemote(serverSourceURL: oURL, force: options.forceODA)
            mode = .localODA(libsDir: AnisetteDataProvider.shared.remoteLibsDir)
        } else if let sUrl = serverURL, let url = URL(string: sUrl) {
            if options.strict {
                let isValid = await AnisetteDataProvider.validateServer(url: url, strict: true)
                guard isValid else {
                    throw CLIError.executionFailed("Strict validation failed for remote server '\(url.absoluteString)'.")
                }
            }
            mode = .remote(server: url)
        } else if LocalAnisetteProvider.validateLibrariesExist(at: AnisetteDataProvider.shared.libsDir) {
            mode = .localODA(libsDir: AnisetteDataProvider.shared.libsDir)
        } else {
            throw CLIError.missingRequiredArgument("""
            An Anisette mode is required. Specify one of:
              --server <url>                 (Direct remote Anisette server)
              --local <dir>                  (Local ADI library directory)
              --oda <url>                    (Remote ODA package / catalog URL)
              --select-server --source <url> (Select interactively from catalog)
              --failover --source <url>      (Automatic catalog failover)
            """)
        }

        var existingData: DeviceData? = nil
        let targetDataURL = options.deviceDataPath.map { URL(fileURLWithPath: $0) } ?? DeviceDataManager.url(for: options.teamID)
        var devPass = options.deviceDataPassword

        if DeviceDataManager.hasData(at: targetDataURL) {
            var loaded = false
            while !loaded {
                if let p = devPass {
                    do {
                        existingData = try DeviceDataManager.load(from: targetDataURL, password: p)
                        devPass = p
                        loaded = true
                    } catch DeviceDataError.invalidPassword {
                        printError("Invalid device data password.")
                        guard let entered = readSecurePassword(prompt: "Enter password for device data ('\(targetDataURL.lastPathComponent)'): "), !entered.isEmpty else {
                            throw CLIError.executionFailed("Operation cancelled.")
                        }
                        devPass = entered
                    } catch {
                        throw CLIError.executionFailed("Loading device data from '\(targetDataURL.path)': \(error.localizedDescription)")
                    }
                } else {
                    guard let entered = readSecurePassword(prompt: "Enter password for device data ('\(targetDataURL.lastPathComponent)'): "), !entered.isEmpty else {
                        throw CLIError.missingRequiredArgument("Device data password cannot be empty.")
                    }
                    devPass = entered
                }
            }
        }

        let provider = AnisetteDataProvider(mode: mode)
        let anisetteData: AnisetteData
        let newAdiPb: Data?

        let errorHandler: @Sendable (Error) async throws -> Bool = { error in
            if case AnisetteError.outdatedV1Server(let serverURL, let reason) = error {
                print()
                if let reason = reason, !reason.isEmpty {
                    printWarning("V3 Anisette is unavailable on '\(serverURL.absoluteString)' (\(reason)).")
                } else {
                    printWarning("V3 Anisette is unavailable on '\(serverURL.absoluteString)'.")
                }
                printWarning("Falling back to legacy V1 mode uses a shared device identity and may increase the risk of Apple ID lockouts.")
                let input = readInteractiveLine(prompt: "Do you want to continue with legacy V1 Anisette? [Y/n]: ", emptyLineBefore: false, emptyLineAfter: true)?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? ""
                if input == "n" || input == "no" {
                    return false
                }
                return true
            }
            return false
        }

        if options.enableFailover {
            let res = try await provider.fetchAnisetteDataWithFailover(
                servers: failoverURLs,
                startIndex: options.startIndex,
                identifier: existingData?.identifier ?? UUID(),
                existingAdiBlob: existingData?.adiBlob,
                onError: errorHandler,
                onSuccess: { winURL in
                    print("Connected to Anisette server: \(winURL.absoluteString)")
                }
            )
            anisetteData = res.data
            newAdiPb = res.newAdiBlob
        } else {
            let res = try await provider.fetchAnisetteData(
                identifier: existingData?.identifier ?? UUID(),
                existingAdiBlob: existingData?.adiBlob,
                onError: errorHandler
            )
            anisetteData = res.data
            newAdiPb = res.newAdiBlob
            print("Anisette headers acquired successfully.")
        }

        if let freshBlob = newAdiPb {
            if devPass == nil {
                if let entered = readSecurePassword(prompt: "Enter password to encrypt new device data (\(targetDataURL.lastPathComponent)): "), !entered.isEmpty {
                    devPass = entered
                }
            }
            if let p = devPass {
                let newData = DeviceData(
                    identifier: existingData?.identifier ?? UUID(),
                    adiBlob: freshBlob,
                    machineID: anisetteData.machineID,
                    localUserID: anisetteData.localUserID
                )
                try DeviceDataManager.save(newData, to: targetDataURL, password: p)
                print("Device data saved and encrypted to: \(targetDataURL.path)")
            }
        }

        return (anisetteData, newAdiPb, targetDataURL, devPass)
    }

    private static func handleCLI2FA(mode: TwoFactorMode, completion: @escaping (TwoFactorAction) -> Void) {
        switch mode {
        case .trustedDevice(let error):
            if let error = error {
                print("\n[2FA] Verification Error: \(error)")
                if let input = readInteractiveLine(prompt: "Press [Enter] to retry code entry, or 'c' to cancel: "), input.lowercased() == "c" {
                    completion(TwoFactorAction.cancel)
                    return
                }
            }
            guard let code = readInteractiveLine(prompt: "Enter 6-digit verification code from your Apple device (or 'p' for phone call/SMS, 'c' to cancel): "), !code.isEmpty else {
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
                if let input = readInteractiveLine(prompt: "Press [Enter] to retry code entry, or 'c' to cancel: "), input.lowercased() == "c" {
                    completion(TwoFactorAction.cancel)
                    return
                }
            }
            let activePhone = phoneNumbers.first(where: { $0.id == activeID })?.number ?? "phone"
            guard let code = readInteractiveLine(prompt: "Enter 6-digit code sent via SMS to \(activePhone) (or 'v' for voice call, 'r' to resend, 'c' to cancel): "), !code.isEmpty else {
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
                if let input = readInteractiveLine(prompt: "Press [Enter] to retry code entry, or 'c' to cancel: "), input.lowercased() == "c" {
                    completion(TwoFactorAction.cancel)
                    return
                }
            }
            let activePhone = phoneNumbers.first(where: { $0.id == activeID })?.number ?? "phone"
            guard let code = readInteractiveLine(prompt: "Enter 6-digit code from voice call to \(activePhone) (or 'r' to resend, 'c' to cancel): "), !code.isEmpty else {
                completion(TwoFactorAction.cancel)
                return
            }
            if code.lowercased() == "c" {
                completion(TwoFactorAction.cancel)
            } else if code.lowercased() == "r" {
                completion(TwoFactorAction.requestPhone(id: activeID, mode: TwoFactorDeliveryMode.voice))
            } else {
                completion(TwoFactorAction.code(code))
            }
        }
    }

    private static func selectAnisetteServerInteractively(sourceURLString: String? = nil) async throws -> String {
        guard let sourceStr = sourceURLString, let url = URL(string: sourceStr) else {
            throw CLIError.missingRequiredArgument("--source <url> is required for interactive server selection.")
        }

        print("Fetching available Anisette servers from \(url.host ?? url.absoluteString)...")
        let provider = AnisetteDataProvider.shared
        let data = try await provider.fetchServerList(from: url)

        let visibleServers = data.servers.filter { !$0.isHidden }
        guard !visibleServers.isEmpty else {
            throw CLIError.executionFailed("No servers found in server list.")
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
            throw CLIError.invalidArgument("Invalid selection.")
        }

        let selected = visibleServers[choice - 1].address
        print("Selected: \(selected)\n")
        return selected
    }
}
