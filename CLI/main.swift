//
//  main.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideStore. All rights reserved.
//

import Foundation
import SideSign

func ~= (pattern: [String]?, value: String) -> Bool {
    return pattern?.contains(value) ?? false
}

private enum FlagRegistry {
    static let commands: [String: [String]] = [
        "sign":             ["sign", "-s", "--sign"],
        "verify":           ["verify", "-v", "--verify"],
        "display":          ["display", "inspect", "-d", "--display", "--inspect", "info"],
        "profile":          ["profile", "-p", "--profile", "prof"],
        "extensions":       ["extensions", "-e", "--extensions", "ext"],
        "archive":          ["archive", "-a", "--archive", "arc"],
        "dev":              ["dev", "developer", "portal", "auth"],
        "p12":              ["p12", "pkcs12"],
        "csr":              ["csr"],
        "anisette":         ["anisette", "-ani", "--anisette", "ani"],
        "removeSignature":  ["remove-signature", "--remove-signature", "unsign", "rs", "rm-sig"]
    ]

    static let sign: [String: [String]] = [
        "p12":              ["--p12", "-p"],
        "password":         ["--password", "-pwd", "-w", "--pass"],
        "profile":          ["--profile", "-m", "-prof"],
        "bundleID":         ["--bundle-id", "-b", "-i", "--id"],
        "usingTeam":        ["--using-team", "-t"],
        "usingTeamID":      ["--using-team-id", "--use-team", "-tid"],
        "entitlements":     ["--entitlements", "-e"],
        "output":           ["--output", "-o"]
    ]

    static let verify: [String: [String]] = [
        "deep":             ["--deep", "-d"],
        "strict":           ["--strict", "-s"]
    ]

    static let inspect: [String: [String]] = [
        "entitlements":     ["--entitlements", "-e"],
        "requirements":     ["--requirements", "-r"]
    ]

    static let extensions: [String: [String]] = [
        "all":              ["--all", "-a"],
        "id":               ["--id", "--bundle-id", "-i", "-b"],
        "output":           ["--output", "-o"]
    ]

    static let p12Create: [String: [String]] = [
        "cert":             ["--cert", "-c"],
        "key":              ["--key", "-k"],
        "password":         ["--password", "-p", "-pwd"],
        "output":           ["--output", "-o"]
    ]

    static let p12Extract: [String: [String]] = [
        "input":            ["--input", "-i"],
        "password":         ["--password", "-p", "-pwd"],
        "outputCert":       ["--output-cert", "-oc", "-c"],
        "outputKey":        ["--output-key", "-ok", "-k"]
    ]

    static let csr: [String: [String]] = [
        "name":             ["--name", "-n"],
        "org":              ["--org", "-o"],
        "country":          ["--country", "-c"],
        "state":            ["--state", "-s"],
        "locality":         ["--locality", "-l"],
        "outputCSR":        ["--output-csr", "-oc", "-csr"],
        "outputKey":        ["--output-key", "-ok", "-key"]
    ]

    static let anisette: [String: [String]] = [
        "json":             ["--json", "-j"],
        "strict":           ["--strict", "-st"],
        "machinePassword":  ["--machine-password", "--adi-password", "-mpwd", "-pwd"],
        "machinePath":      ["--machine-path", "--adi-path", "-mp"],
        "usingTeam":        ["--using-team", "--select-team", "-t"],
        "usingTeamID":      ["--using-team-id", "--select-team-id", "--use-team", "-tid"],
        "local":            ["--local", "--local-adi", "-l"],
        "oda":              ["--oda", "-oda"],
        "forceODA":         ["--force-oda", "--force-download-oda"],
        "server":           ["--server", "--url", "-srv", "-u"],
        "source":           ["--source", "--list", "-src"],
        "anisetteUDID":     ["--anisette-device-udid", "--anisette-udid", "-udid"],
        "selectServer":     ["--select-server", "-sel", "-s"],
        "failover":         ["--failover", "--auto-failover", "-f"],
        "startIndex":       ["--start-index", "-idx"]
    ]
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
      dev                   Apple ID authentication, 2FA, and Developer Portal operations
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
      sidesign sign app.ipa --p12 dev.p12 -p secret --profile dev.mobileprovision -o signed.ipa

      # Inspect an App Bundle or Mach-O Binary:
      sidesign inspect app.ipa -e

      # Dump Provisioning Profile details:
      sidesign profile dump embedded.mobileprovision

      # Remove extensions from an IPA:
      sidesign extensions remove app.ipa --all -o app_no_ext.ipa

      # Apple Developer Portal login & 2FA:
      sidesign dev login --apple-id developer@example.com

      # Re-authenticate active account with new password / token refresh:
      sidesign dev relogin

      # List saved account sessions:
      sidesign dev list

      # Select active default team (by list index or Team ID):
      sidesign dev select-team 1
      sidesign dev select-team-id TEAM123456

      # Use a specific Team's session (by list index or Team ID):
      sidesign dev certs -t 1
      sidesign dev certs -tid TEAM123456

      # Login with interactive Anisette server selection:
      sidesign dev login -u developer@example.com -sel

      # List available public Anisette servers:
      sidesign anisette servers

      # Interactively pick a server from the public list:
      sidesign anisette -sel

      # Fetch Anisette headers via remote ODA package:
      sidesign anisette --oda https://example.com/oda.json

      # Register a new device UDID:
      sidesign dev devices register -n "My iPhone" -u <DEVICE_UDID>

      # Register an App ID:
      sidesign dev appids register -n "MyApp" -b "com.example.myapp"

      # Create an App Group:
      sidesign dev appgroups create -n "MyAppGroup" -g "group.com.example.myapp"

      # Download a Provisioning Profile:
      sidesign dev profiles download -b "com.example.myapp" -o dev.mobileprovision

      # Generate a Certificate Signing Request:
      sidesign csr create -n "John Doe" -o "My Org" -oc request.csr -ok private.key

      # Package Certificate + Key into P12:
      sidesign p12 create -c cert.der -k private.key -p secret -o dev.p12

      # Generate Anisette headers using local ADI libraries:
      sidesign anisette -l /path/to/adi/Libraries -j
    """)
}

private func parseSignContext(args: [String]) throws -> SignContext {
    let flags = FlagRegistry.sign
    var targetPath: String?
    var p12Path: String?
    var password = ""
    var profilePath: String?
    var bundleID: String?
    var teamID: String?
    var entitlementsPath: String?
    var outputPath: String?

    var i = 0
    func nextVal() -> String? {
        guard i + 1 < args.count, !args[i + 1].hasPrefix("-") else { return nil }
        i += 1
        return args[i]
    }

    while i < args.count {
        let arg = args[i]
        switch arg {
        case flags["p12"]:              p12Path          = nextVal()
        case flags["password"]:         password         = nextVal() ?? ""
        case flags["profile"]:          profilePath      = nextVal()
        case flags["bundleID"]:         bundleID         = nextVal()
        case flags["usingTeam"]:        teamID           = try CommandHandler.resolveTeamIDFromIndex(nextVal())
        case flags["usingTeamID"]:      teamID           = try nextVal().map { try CommandHandler.validateAndResolveTeamID($0) }
        case flags["entitlements"]:     entitlementsPath = nextVal()
        case flags["output"]:           outputPath       = nextVal()
        default:
            if !arg.hasPrefix("-") && targetPath == nil {
                targetPath = arg
            }
        }
        i += 1
    }

    guard let target = targetPath else {
        throw CLIError.missingRequiredArgument("No target IPA, .app, or binary specified.")
    }
    guard let p12 = p12Path else {
        throw CLIError.missingRequiredArgument("P12 certificate is required for signing (--p12 <path>).")
    }

    return SignContext(
        targetPath: target,
        p12Path: p12,
        password: password,
        profilePath: profilePath,
        bundleID: bundleID,
        teamID: teamID,
        entitlementsPath: entitlementsPath,
        outputPath: outputPath
    )
}

private func parseVerifyContext(args: [String]) throws -> VerifyContext {
    let flags = FlagRegistry.verify
    var targetPath: String?
    var isDeep = false
    var isStrict = false

    for arg in args {
        switch arg {
        case flags["deep"]:   isDeep   = true
        case flags["strict"]: isStrict = true
        default:
            if !arg.hasPrefix("-") && targetPath == nil {
                targetPath = arg
            }
        }
    }

    guard let target = targetPath else {
        throw CLIError.missingRequiredArgument("No target specified for verification.")
    }
    return VerifyContext(targetPath: target, isDeep: isDeep, isStrict: isStrict)
}

private func parseInspectContext(args: [String]) throws -> InspectContext {
    let flags = FlagRegistry.inspect
    var targetPath: String?
    var dumpEntitlements = false
    var dumpRequirements = false

    for arg in args {
        switch arg {
        case flags["entitlements"]: dumpEntitlements = true
        case flags["requirements"]: dumpRequirements = true
        default:
            if !arg.hasPrefix("-") && targetPath == nil {
                targetPath = arg
            }
        }
    }

    guard let target = targetPath else {
        throw CLIError.missingRequiredArgument("No target specified for display/inspection.")
    }
    return InspectContext(targetPath: target, dumpEntitlements: dumpEntitlements, dumpRequirements: dumpRequirements)
}

private func parseProfileContext(args: [String]) throws -> ProfileContext {
    guard args.count >= 2 else {
        throw CLIError.missingRequiredArgument("""
        Usage:
          sidesign profile dump <path/to/profile.mobileprovision>
          sidesign profile validate <path/to/profile.mobileprovision>
        """)
    }

    let actionStr = args[0]
    let path = args[1]
    let action: ProfileContext.Action
    switch actionStr {
    case "dump", "inspect", "-d": action = .dump
    case "validate", "-v":        action = .validate
    default:
        throw CLIError.invalidArgument("Unknown profile action: \(actionStr)")
    }
    return ProfileContext(action: action, profilePath: path)
}

private func parseExtensionsContext(args: [String]) throws -> ExtensionsContext {
    guard args.count >= 2 else {
        throw CLIError.missingRequiredArgument("""
        Usage:
          sidesign extensions list <app_or_ipa>
          sidesign extensions remove <app_or_ipa> [--all | --id <bundle_id>] [--output <path>]
        """)
    }

    let actionStr = args[0]
    let target = args[1]

    switch actionStr {
    case "list", "ls", "-l":
        return ExtensionsContext(targetPath: target, action: .list)
    case "remove", "rm", "-r":
        let flags = FlagRegistry.extensions
        var removeAll = false
        var targetID: String?
        var outputPath: String?

        var idx = 2
        func nextVal() -> String? {
            guard idx + 1 < args.count, !args[idx + 1].hasPrefix("-") else { return nil }
            idx += 1
            return args[idx]
        }

        while idx < args.count {
            switch args[idx] {
            case flags["all"]:      removeAll  = true
            case flags["id"]:       targetID   = nextVal()
            case flags["output"]:   outputPath = nextVal()
            default:                break
            }
            idx += 1
        }
        return ExtensionsContext(targetPath: target, action: .remove(all: removeAll, targetID: targetID, outputPath: outputPath))
    default:
        throw CLIError.invalidArgument("Unknown extensions action: \(actionStr)")
    }
}

private func parseArchiveContext(args: [String]) throws -> ArchiveContext {
    guard args.count >= 2 else {
        throw CLIError.missingRequiredArgument("""
        Usage:
          sidesign archive unzip <input.ipa> [--output <directory>]
          sidesign archive zip <input.app> [--output <output.ipa>]
        """)
    }

    let actionStr = args[0]
    let input = args[1]
    var outputPath: String?
    if args.count >= 4 && (args[2] == "--output" || args[2] == "-o") {
        outputPath = args[3]
    }

    switch actionStr {
    case "unzip", "unpack", "-u":
        return ArchiveContext(action: .unzip(inputPath: input, outputPath: outputPath))
    case "zip", "pack", "-z":
        return ArchiveContext(action: .zip(inputPath: input, outputPath: outputPath))
    default:
        throw CLIError.invalidArgument("Unknown archive action: \(actionStr)")
    }
}

private func parseP12Context(args: [String]) throws -> P12Context {
    guard args.count >= 1 else {
        throw CLIError.missingRequiredArgument("""
        Usage:
          sidesign p12 create --cert <cert.cer/der> --key <private.key> [--password <pwd>] --output <out.p12>
          sidesign p12 extract --input <in.p12> [--password <pwd>] --output-cert <cert.der> --output-key <key.der>
        """)
    }

    let actionStr = args[0]
    switch actionStr {
    case "create", "make", "-c":
        let flags = FlagRegistry.p12Create
        var certPath: String?
        var keyPath: String?
        var password: String?
        var outputPath: String?

        var idx = 1
        func nextVal() -> String? {
            guard idx + 1 < args.count, !args[idx + 1].hasPrefix("-") else { return nil }
            idx += 1
            return args[idx]
        }

        while idx < args.count {
            switch args[idx] {
            case flags["cert"]:     certPath   = nextVal()
            case flags["key"]:      keyPath    = nextVal()
            case flags["password"]: password   = nextVal()
            case flags["output"]:   outputPath = nextVal()
            default:                break
            }
            idx += 1
        }

        guard let cert = certPath, let key = keyPath, let out = outputPath else {
            throw CLIError.missingRequiredArgument("Usage: sidesign p12 create --cert <cert.cer> --key <key.key> [--password <pwd>] --output <out.p12>")
        }
        return P12Context(action: .create(certPath: cert, keyPath: key, password: password, outputPath: out))

    case "extract", "-x":
        let flags = FlagRegistry.p12Extract
        var inputPath: String?
        var password: String?
        var outCertPath: String?
        var outKeyPath: String?

        var idx = 1
        func nextVal() -> String? {
            guard idx + 1 < args.count, !args[idx + 1].hasPrefix("-") else { return nil }
            idx += 1
            return args[idx]
        }

        while idx < args.count {
            switch args[idx] {
            case flags["input"]:        inputPath   = nextVal()
            case flags["password"]:     password    = nextVal()
            case flags["outputCert"]:   outCertPath = nextVal()
            case flags["outputKey"]:    outKeyPath  = nextVal()
            default:                    break
            }
            idx += 1
        }

        guard let input = inputPath, let outCert = outCertPath, let outKey = outKeyPath else {
            throw CLIError.missingRequiredArgument("Usage: sidesign p12 extract --input <in.p12> [--password <pwd>] --output-cert <cert.der> --output-key <key.der>")
        }
        return P12Context(action: .extract(inputPath: input, password: password, outCertPath: outCert, outKeyPath: outKey))

    default:
        throw CLIError.invalidArgument("Unknown p12 action: \(actionStr)")
    }
}

private func parseCSRContext(args: [String]) throws -> CSRContext {
    let flags = FlagRegistry.csr
    var commonName = "SideSign"
    var org = "SideSign"
    var country = "US"
    var state = "CA"
    var locality = "Los Angeles"
    var outCSR: String?
    var outKey: String?

    var idx = 0
    func nextVal() -> String? {
        guard idx + 1 < args.count, !args[idx + 1].hasPrefix("-") else { return nil }
        idx += 1
        return args[idx]
    }

    while idx < args.count {
        switch args[idx] {
        case flags["name"]:         commonName = nextVal() ?? commonName
        case flags["org"]:          org        = nextVal() ?? org
        case flags["country"]:      country    = nextVal() ?? country
        case flags["state"]:        state      = nextVal() ?? state
        case flags["locality"]:     locality   = nextVal() ?? locality
        case flags["outputCSR"]:    outCSR     = nextVal()
        case flags["outputKey"]:    outKey     = nextVal()
        default:                    break
        }
        idx += 1
    }

    guard let csrPath = outCSR, let keyPath = outKey else {
        throw CLIError.missingRequiredArgument("""
        Usage:
          sidesign csr create [--name <commonName>] [--org <org>] --output-csr <request.csr> --output-key <private.key>
        """)
    }

    return CSRContext(
        commonName: commonName,
        organization: org,
        country: country,
        state: state,
        locality: locality,
        outputCSR: csrPath,
        outputKey: keyPath
    )
}

private func parseAnisetteContext(args: [String]) throws -> AnisetteContext {
    if args.first == "servers" || args.first == "list" || args.first == "ls" {
        var sourceURLStr: String?
        var idx = 1
        func nextVal() -> String? {
            guard idx + 1 < args.count, !args[idx + 1].hasPrefix("-") else { return nil }
            idx += 1
            return args[idx]
        }

        while idx < args.count {
            let a = args[idx]
            switch a {
            case "--source", "--list", "--url", "-u", "-src":
                sourceURLStr = nextVal()
            default:
                if a.hasPrefix("http://") || a.hasPrefix("https://") {
                    sourceURLStr = a
                }
            }
            idx += 1
        }

        guard let src = sourceURLStr else {
            throw CLIError.missingRequiredArgument("Server list URL is required. Usage: sidesign anisette servers --source <url>")
        }
        return AnisetteContext(action: .listServers(sourceURL: src))
    }

    let flags = FlagRegistry.anisette
    var serverURL: String?
    var localDir: String?
    var odaURL: String?
    var sourceURLStr: String?
    var anisetteDeviceUDID: String?
    var deviceDataPath: String?
    var deviceDataPassword: String?
    var teamID: String?
    var selectServer = false
    var enableFailover = false
    var startIndex = 0
    var asJSON = false
    var strict = false
    var forceODA = false

    var idx = 0
    func nextVal() -> String? {
        guard idx + 1 < args.count, !args[idx + 1].hasPrefix("-") else { return nil }
        idx += 1
        return args[idx]
    }

    while idx < args.count {
        let arg = args[idx]
        switch arg {
        case flags["json"]:             asJSON             = true
        case flags["strict"]:           strict             = true
        case flags["machinePassword"]:  deviceDataPassword = nextVal()
        case flags["machinePath"]:      deviceDataPath     = nextVal()
        case flags["usingTeam"]:        teamID             = try CommandHandler.resolveTeamIDFromIndex(nextVal())
        case flags["usingTeamID"]:      teamID             = try nextVal().map { try CommandHandler.validateAndResolveTeamID($0) }
        case flags["local"]:            localDir           = nextVal()
        case flags["oda"]:              odaURL             = nextVal()
        case flags["forceODA"]:         forceODA           = true
        case flags["server"]:           serverURL          = nextVal()
        case flags["source"]:           sourceURLStr       = nextVal()
        case flags["anisetteUDID"]:     anisetteDeviceUDID = nextVal()
        case flags["selectServer"]:     selectServer       = true
        case flags["failover"]:         enableFailover     = true
        case flags["startIndex"]:       startIndex         = nextVal().flatMap(Int.init) ?? 0
        default:
            if arg.hasPrefix("http://") || arg.hasPrefix("https://") {
                serverURL = arg
            }
        }
        idx += 1
    }

    return AnisetteContext(action: .generate(
        serverURL: serverURL,
        localDir: localDir,
        odaURL: odaURL,
        sourceURLStr: sourceURLStr,
        anisetteDeviceUDID: anisetteDeviceUDID,
        deviceDataPath: deviceDataPath,
        deviceDataPassword: deviceDataPassword,
        teamID: teamID,
        selectServer: selectServer,
        enableFailover: enableFailover,
        startIndex: startIndex,
        asJSON: asJSON,
        strict: strict,
        forceODA: forceODA
    ))
}

private func run(rawArgs: [String]) async throws {
    if rawArgs.isEmpty || rawArgs.contains("-h") || rawArgs.contains("--help") || rawArgs.contains("help") {
        printUsage()
        return
    }

    if rawArgs.contains("--verbose") || rawArgs.contains("-v") || rawArgs.contains("-vv") || rawArgs.contains("--debug") || rawArgs.contains("-d") {
        SideSignLogging.setLogging(true)
    }

    print()
    defer { print() }

    let nonGlobalArgs = rawArgs.filter { !["-v", "--verbose", "-vv", "--debug", "-d"].contains($0) }
    guard let command = nonGlobalArgs.first else {
        printUsage()
        return
    }
    let subArgs = Array(nonGlobalArgs.dropFirst())

    let cmd = FlagRegistry.commands
    switch command {
    case cmd["sign"]:
        let ctx = try parseSignContext(args: subArgs)
        try await CommandHandler.handleSign(context: ctx)
    case cmd["verify"]:
        let ctx = try parseVerifyContext(args: subArgs)
        try CommandHandler.handleVerify(context: ctx)
    case cmd["display"]:
        let ctx = try parseInspectContext(args: subArgs)
        try CommandHandler.handleDisplay(context: ctx)
    case cmd["profile"]:
        let ctx = try parseProfileContext(args: subArgs)
        try CommandHandler.handleProfile(context: ctx)
    case cmd["extensions"]:
        let ctx = try parseExtensionsContext(args: subArgs)
        try CommandHandler.handleExtensions(context: ctx)
    case cmd["archive"]:
        let ctx = try parseArchiveContext(args: subArgs)
        try CommandHandler.handleArchive(context: ctx)
    case cmd["dev"]:
        let req = try PortalCommandsParser.parse(args: subArgs)
        try await CommandHandler.handlePortal(request: req)
    case cmd["p12"]:
        let ctx = try parseP12Context(args: subArgs)
        try CommandHandler.handleP12(context: ctx)
    case cmd["csr"]:
        let ctx = try parseCSRContext(args: subArgs)
        try CommandHandler.handleCSR(context: ctx)
    case cmd["anisette"]:
        let ctx = try parseAnisetteContext(args: subArgs)
        try await CommandHandler.handleAnisette(context: ctx)
    case cmd["removeSignature"]:
        let ctx = RemoveSignatureContext(targetPath: subArgs.first ?? "")
        guard !ctx.targetPath.isEmpty else {
            throw CLIError.missingRequiredArgument("Usage: sidesign remove-signature <path_to_binary_or_bundle>")
        }
        try CommandHandler.handleRemoveSignature(context: ctx)
    default:
        if FileManager.default.fileExists(atPath: command) {
            let ctx = try parseSignContext(args: [command] + subArgs)
            try await CommandHandler.handleSign(context: ctx)
        } else {
            printUsage()
            throw CLIError.invalidArgument("Unknown command '\(command)'.")
        }
    }
}

func main() async {
    do {
        try await run(rawArgs: Array(CommandLine.arguments.dropFirst()))
    } catch {
        CommandHandler.printError(error.localizedDescription)
        exit(1)
    }
}

await main()
