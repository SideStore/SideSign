//
//  main.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideStore. All rights reserved.
//

import Foundation
import SideSign

func terminate(code: Int32 = 0) -> Never {
    exit(code)
}

CommandHandler.exitHandler = { code in
    terminate(code: code)
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
      sidesign dev select-team-id 8884ZS2845

      # Use a specific Team's session (by list index or Team ID):
      sidesign dev certs -t 1
      sidesign dev certs -tid 8884ZS2845

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

private func parseSignContext(args: [String]) -> SignContext {
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
        } else if arg == "--password" || arg == "-pwd" || arg == "-w" || arg == "--pass" {
            if i + 1 < args.count { password = args[i + 1]; i += 1 }
        } else if arg == "--profile" || arg == "-m" || arg == "-prof" {
            if i + 1 < args.count { profilePath = args[i + 1]; i += 1 }
        } else if arg == "--bundle-id" || arg == "-b" || arg == "-i" || arg == "--id" {
            if i + 1 < args.count { bundleID = args[i + 1]; i += 1 }
        } else if arg == "--using-team" || arg == "-t" {
            let nextVal = (i + 1 < args.count && !args[i + 1].hasPrefix("-")) ? args[i + 1] : nil
            if nextVal != nil { i += 1 }
            teamID = CommandHandler.resolveTeamIDFromIndex(nextVal)
        } else if arg == "--using-team-id" || arg == "--use-team" || arg == "-tid" {
            if i + 1 < args.count {
                teamID = CommandHandler.validateAndResolveTeamID(args[i + 1])
                i += 1
            }
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
        CommandHandler.printError("No target IPA, .app, or binary specified.")
        terminate(code: 1)
    }
    guard let p12 = p12Path else {
        CommandHandler.printError("P12 certificate is required for signing (--p12 <path>).")
        terminate(code: 1)
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

private func parseVerifyContext(args: [String]) -> VerifyContext {
    var targetPath: String?
    var isDeep = false
    var isStrict = false

    for arg in args {
        if arg == "--deep" || arg == "-d" {
            isDeep = true
        } else if arg == "--strict" || arg == "-s" {
            isStrict = true
        } else if !arg.hasPrefix("-") && targetPath == nil {
            targetPath = arg
        }
    }

    guard let target = targetPath else {
        CommandHandler.printError("No target specified for verification.")
        terminate(code: 1)
    }
    return VerifyContext(targetPath: target, isDeep: isDeep, isStrict: isStrict)
}

private func parseInspectContext(args: [String]) -> InspectContext {
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
        CommandHandler.printError("No target specified for display/inspection.")
        terminate(code: 1)
    }
    return InspectContext(targetPath: target, dumpEntitlements: dumpEntitlements, dumpRequirements: dumpRequirements)
}

private func parseProfileContext(args: [String]) -> ProfileContext {
    guard args.count >= 2 else {
        CommandHandler.printError("""
        Usage:
          sidesign profile dump <path/to/profile.mobileprovision>
          sidesign profile validate <path/to/profile.mobileprovision>
        """)
        terminate(code: 1)
    }

    let actionStr = args[0]
    let path = args[1]
    let action: ProfileContext.Action
    switch actionStr {
    case "dump", "inspect", "-d": action = .dump
    case "validate", "-v":        action = .validate
    default:
        CommandHandler.printError("Unknown profile action: \(actionStr)")
        terminate(code: 1)
    }
    return ProfileContext(action: action, profilePath: path)
}

private func parseExtensionsContext(args: [String]) -> ExtensionsContext {
    guard args.count >= 2 else {
        CommandHandler.printError("""
        Usage:
          sidesign extensions list <app_or_ipa>
          sidesign extensions remove <app_or_ipa> [--all | --id <bundle_id>] [--output <path>]
        """)
        terminate(code: 1)
    }

    let actionStr = args[0]
    let target = args[1]

    switch actionStr {
    case "list", "ls", "-l":
        return ExtensionsContext(targetPath: target, action: .list)
    case "remove", "rm", "-r":
        var removeAll = false
        var targetID: String?
        var outputPath: String?

        var idx = 2
        while idx < args.count {
            let a = args[idx]
            if a == "--all" || a == "-a" { removeAll = true }
            else if a == "--id" || a == "--bundle-id" || a == "-i" || a == "-b" {
                if idx + 1 < args.count { targetID = args[idx + 1]; idx += 1 }
            } else if a == "--output" || a == "-o" {
                if idx + 1 < args.count { outputPath = args[idx + 1]; idx += 1 }
            }
            idx += 1
        }
        return ExtensionsContext(targetPath: target, action: .remove(all: removeAll, targetID: targetID, outputPath: outputPath))
    default:
        CommandHandler.printError("Unknown extensions action: \(actionStr)")
        terminate(code: 1)
    }
}

private func parseArchiveContext(args: [String]) -> ArchiveContext {
    guard args.count >= 2 else {
        CommandHandler.printError("""
        Usage:
          sidesign archive unzip <input.ipa> [--output <directory>]
          sidesign archive zip <input.app> [--output <output.ipa>]
        """)
        terminate(code: 1)
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
        CommandHandler.printError("Unknown archive action: \(actionStr)")
        terminate(code: 1)
    }
}

private func parseP12Context(args: [String]) -> P12Context {
    guard args.count >= 1 else {
        CommandHandler.printError("""
        Usage:
          sidesign p12 create --cert <cert.cer/der> --key <private.key> [--password <pwd>] --output <out.p12>
          sidesign p12 extract --input <in.p12> [--password <pwd>] --output-cert <cert.der> --output-key <key.der>
        """)
        terminate(code: 1)
    }

    let actionStr = args[0]
    switch actionStr {
    case "create", "make", "-c":
        var certPath: String?
        var keyPath: String?
        var password: String?
        var outputPath: String?

        var idx = 1
        while idx < args.count {
            if (args[idx] == "--cert" || args[idx] == "-c") && idx + 1 < args.count { certPath = args[idx + 1]; idx += 1 }
            if (args[idx] == "--key" || args[idx] == "-k") && idx + 1 < args.count { keyPath = args[idx + 1]; idx += 1 }
            if (args[idx] == "--password" || args[idx] == "-p" || args[idx] == "-pwd") && idx + 1 < args.count { password = args[idx + 1]; idx += 1 }
            if (args[idx] == "--output" || args[idx] == "-o") && idx + 1 < args.count { outputPath = args[idx + 1]; idx += 1 }
            idx += 1
        }

        guard let cert = certPath, let key = keyPath, let out = outputPath else {
            CommandHandler.printError("Usage: sidesign p12 create --cert <cert.cer> --key <key.key> [--password <pwd>] --output <out.p12>")
            terminate(code: 1)
        }
        return P12Context(action: .create(certPath: cert, keyPath: key, password: password, outputPath: out))

    case "extract", "-x":
        var inputPath: String?
        var password: String?
        var outCertPath: String?
        var outKeyPath: String?

        var idx = 1
        while idx < args.count {
            if (args[idx] == "--input" || args[idx] == "-i") && idx + 1 < args.count { inputPath = args[idx + 1]; idx += 1 }
            if (args[idx] == "--password" || args[idx] == "-p" || args[idx] == "-pwd") && idx + 1 < args.count { password = args[idx + 1]; idx += 1 }
            if (args[idx] == "--output-cert" || args[idx] == "-oc" || args[idx] == "-c") && idx + 1 < args.count { outCertPath = args[idx + 1]; idx += 1 }
            if (args[idx] == "--output-key" || args[idx] == "-ok" || args[idx] == "-k") && idx + 1 < args.count { outKeyPath = args[idx + 1]; idx += 1 }
            idx += 1
        }

        guard let input = inputPath, let outCert = outCertPath, let outKey = outKeyPath else {
            CommandHandler.printError("Usage: sidesign p12 extract --input <in.p12> [--password <pwd>] --output-cert <cert.der> --output-key <key.der>")
            terminate(code: 1)
        }
        return P12Context(action: .extract(inputPath: input, password: password, outCertPath: outCert, outKeyPath: outKey))

    default:
        CommandHandler.printError("Unknown p12 action: \(actionStr)")
        terminate(code: 1)
    }
}

private func parseCSRContext(args: [String]) -> CSRContext {
    var commonName = "SideSign"
    var org = "SideSign"
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
        else if a == "--state" || a == "-s" { if idx + 1 < args.count { state = args[idx + 1]; idx += 1 } }
        else if a == "--locality" || a == "-l" { if idx + 1 < args.count { locality = args[idx + 1]; idx += 1 } }
        else if a == "--output-csr" || a == "-oc" || a == "-csr" { if idx + 1 < args.count { outCSR = args[idx + 1]; idx += 1 } }
        else if a == "--output-key" || a == "-ok" || a == "-key" { if idx + 1 < args.count { outKey = args[idx + 1]; idx += 1 } }
        idx += 1
    }

    guard let csrPath = outCSR, let keyPath = outKey else {
        CommandHandler.printError("""
        Usage:
          sidesign csr create [--name <commonName>] [--org <org>] --output-csr <request.csr> --output-key <private.key>
        """)
        terminate(code: 1)
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

private func parseAnisetteContext(args: [String]) -> AnisetteContext {
    if args.first == "servers" || args.first == "list" || args.first == "ls" {
        var sourceURLStr: String?
        var idx = 1
        while idx < args.count {
            let a = args[idx]
            if (a == "--source" || a == "--list" || a == "--url" || a == "-u" || a == "-src") && idx + 1 < args.count {
                sourceURLStr = args[idx + 1]
                idx += 1
            } else if a.hasPrefix("http://") || a.hasPrefix("https://") {
                sourceURLStr = a
            }
            idx += 1
        }

        guard let src = sourceURLStr else {
            CommandHandler.printError("Server list URL is required. Usage: sidesign anisette servers --source <url>")
            terminate(code: 1)
        }
        return AnisetteContext(action: .listServers(sourceURL: src))
    }

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

    var idx = 0
    while idx < args.count {
        let a = args[idx]
        if a == "--json" || a == "-j" { asJSON = true }
        else if a == "--strict" || a == "-st" { strict = true }
        else if (a == "--machine-password" || a == "--adi-password" || a == "-mpwd" || a == "-pwd") && idx + 1 < args.count {
            deviceDataPassword = args[idx + 1]
            idx += 1
        } else if (a == "--machine-path" || a == "--adi-path" || a == "-mp") && idx + 1 < args.count {
            deviceDataPath = args[idx + 1]
            idx += 1
        } else if a == "--using-team" || a == "--select-team" || a == "-t" {
            let nextVal = (idx + 1 < args.count && !args[idx + 1].hasPrefix("-")) ? args[idx + 1] : nil
            if nextVal != nil { idx += 1 }
            teamID = CommandHandler.resolveTeamIDFromIndex(nextVal)
        } else if (a == "--using-team-id" || a == "--select-team-id" || a == "--use-team" || a == "-tid") && idx + 1 < args.count {
            teamID = CommandHandler.validateAndResolveTeamID(args[idx + 1])
            idx += 1
        } else if (a == "--local" || a == "--local-adi" || a == "-l") && idx + 1 < args.count {
            localDir = args[idx + 1]
            idx += 1
        } else if (a == "--oda" || a == "-oda") && idx + 1 < args.count {
            odaURL = args[idx + 1]
            idx += 1
        } else if (a == "--server" || a == "--url" || a == "-srv" || a == "-u") && idx + 1 < args.count {
            serverURL = args[idx + 1]
            idx += 1
        } else if (a == "--source" || a == "--list" || a == "-src") && idx + 1 < args.count {
            sourceURLStr = args[idx + 1]
            idx += 1
        } else if (a == "--anisette-device-udid" || a == "--anisette-udid" || a == "-udid") && idx + 1 < args.count {
            anisetteDeviceUDID = args[idx + 1]
            idx += 1
        } else if a == "--select-server" || a == "-sel" || a == "-s" {
            selectServer = true
        } else if a == "--failover" || a == "--auto-failover" || a == "-f" {
            enableFailover = true
        } else if (a == "--start-index" || a == "-idx") && idx + 1 < args.count {
            if let idxVal = Int(args[idx + 1]) { startIndex = idxVal; idx += 1 }
        } else if a.hasPrefix("http://") || a.hasPrefix("https://") {
            serverURL = a
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
        strict: strict
    ))
}

private func parsePortalOptions(args: [String]) -> (options: PortalOptions, appleID: String?) {
    var appleID: String?
    var password: String?
    var sessionPath: String?
    var encryptPassword: String?
    var deviceDataPath: String?
    var deviceDataPassword: String?
    var teamID: String?
    var anisetteURL: String?
    var localAnisetteDir: String?
    var odaURL: String?
    var selectServer = false
    var strict = false

    var sourceURLStr: String?
    var enableFailover = false
    var startIndex = 0

    var i = 0
    while i < args.count {
        let a = args[i]
        if a == "--apple-id" || a == "-u" || a == "-a" {
            if i + 1 < args.count { appleID = args[i + 1]; i += 1 }
        } else if a == "--password" || a == "-p" || a == "-pwd" || a == "-w" {
            if i + 1 < args.count { password = args[i + 1]; i += 1 }
        } else if a == "--session" || a == "--session-file" || a == "-s" {
            if i + 1 < args.count { sessionPath = args[i + 1]; i += 1 }
        } else if a == "--using-team" || a == "--select-team" || a == "-t" {
            let nextVal = (i + 1 < args.count && !args[i + 1].hasPrefix("-")) ? args[i + 1] : nil
            if nextVal != nil { i += 1 }
            teamID = CommandHandler.resolveTeamIDFromIndex(nextVal)
        } else if a == "--using-team-id" || a == "--select-team-id" || a == "--use-team" || a == "-tid" {
            if i + 1 < args.count {
                teamID = CommandHandler.validateAndResolveTeamID(args[i + 1])
                i += 1
            }
        } else if a == "--encrypt-password" || a == "-ep" {
            if i + 1 < args.count { encryptPassword = args[i + 1]; i += 1 }
        } else if a == "--machine-password" || a == "--adi-password" || a == "-mpwd" {
            if i + 1 < args.count { deviceDataPassword = args[i + 1]; i += 1 }
        } else if a == "--machine-path" || a == "--adi-path" || a == "-mp" {
            if i + 1 < args.count { deviceDataPath = args[i + 1]; i += 1 }
        } else if a == "--anisette-url" || a == "--anisette" || a == "--server" || a == "-srv" {
            if i + 1 < args.count { anisetteURL = args[i + 1]; i += 1 }
        } else if a == "--local-anisette" || a == "--local-adi" || a == "--local" || a == "-l" {
            if i + 1 < args.count { localAnisetteDir = args[i + 1]; i += 1 }
        } else if a == "--oda" || a == "-oda" {
            if i + 1 < args.count { odaURL = args[i + 1]; i += 1 }
        } else if a == "--source" || a == "--list" || a == "-src" {
            if i + 1 < args.count { sourceURLStr = args[i + 1]; i += 1 }
        } else if a == "--select-server" || a == "-sel" {
            selectServer = true
        } else if a == "--failover" || a == "--auto-failover" || a == "-f" {
            enableFailover = true
        } else if a == "--start-index" || a == "-idx" {
            if i + 1 < args.count, let idxVal = Int(args[i + 1]) { startIndex = idxVal; i += 1 }
        } else if a == "--strict" || a == "-st" {
            strict = true
        }
        i += 1
    }

    let opts = PortalOptions(
        sessionPath: sessionPath,
        password: password,
        encryptPassword: encryptPassword,
        deviceDataPath: deviceDataPath,
        deviceDataPassword: deviceDataPassword,
        teamID: teamID,
        anisetteURL: anisetteURL,
        localAnisetteDir: localAnisetteDir,
        odaURL: odaURL,
        selectServer: selectServer,
        strict: strict,
        sourceURLStr: sourceURLStr,
        enableFailover: enableFailover,
        startIndex: startIndex
    )
    return (opts, appleID)
}

private func parsePortalRequestContext(args: [String]) -> PortalRequestContext {
    guard !args.isEmpty else {
        CommandHandler.printError("""
        Usage:
          sidesign dev login --apple-id <email> [--password <pwd>] [--session <path>] [--encrypt-password <pwd>]
          sidesign dev relogin [--session <path>] [--password <pwd>]
          sidesign dev logout [--session <path>]
          sidesign dev status [--session <path>] [--password <pwd>]
          sidesign dev list
          sidesign dev select-team <index>
          sidesign dev select-team-id <team_id>
          sidesign dev teams [--session <path>]
          sidesign dev devices list / register --name <name> --udid <udid> [--session <path>]
          sidesign dev certs list / create / revoke --id <id> [--session <path>]
          sidesign dev appids list / register --name <name> --bundle-id <id> / delete --id <id> [--session <path>]
          sidesign dev appgroups list / create --name <name> --group-id <id> / assign --app-id <id> --group-id <id> [--session <path>]
          sidesign dev profiles list / download --bundle-id <id> [--output <path>] / delete --id <id> [--session <path>]
        """)
        terminate(code: 1)
    }

    let action = args[0]
    let subArgs = Array(args.dropFirst())
    let (portalOpts, appleID) = parsePortalOptions(args: subArgs)

    if action == "list" || action == "sessions" || action == "ls" {
        return .list
    }

    if action == "select-team" || action == "set-team" {
        let index = subArgs.first
        return .selectTeam(index: index)
    }

    if action == "select-team-id" || action == "set-team-id" {
        guard let tID = subArgs.first else {
            CommandHandler.printError("Team ID required (e.g. sidesign dev select-team-id 8884ZS2845)")
            terminate(code: 1)
        }
        return .selectTeamID(teamID: tID)
    }

    if action == "logout" {
        return .logout(sessionPath: portalOpts.sessionPath, teamID: portalOpts.teamID)
    }

    if action == "status" {
        return .status(sessionPath: portalOpts.sessionPath, password: portalOpts.password, encryptPassword: portalOpts.encryptPassword, teamID: portalOpts.teamID)
    }

    if action == "relogin" {
        return .relogin(portalOpts)
    }

    if action == "login" {
        guard let email = appleID else {
            CommandHandler.printError("Apple ID is required for login (--apple-id <email>).")
            terminate(code: 1)
        }
        return .login(PortalLoginOptions(appleID: email, portalOptions: portalOpts))
    }

    if action == "teams" {
        return .teams(portalOpts)
    }

    if action == "devices" {
        let subAction: PortalDeviceOptions.Action
        if subArgs.contains("register") || subArgs.contains("add") {
            var name: String?
            var udid: String?
            var idx = 0
            while idx < subArgs.count {
                if (subArgs[idx] == "--name" || subArgs[idx] == "-n") && idx + 1 < subArgs.count { name = subArgs[idx + 1]; idx += 1 }
                if (subArgs[idx] == "--udid" || subArgs[idx] == "-u" || subArgs[idx] == "--id" || subArgs[idx] == "-i") && idx + 1 < subArgs.count { udid = subArgs[idx + 1]; idx += 1 }
                idx += 1
            }
            guard let devName = name, let devUDID = udid else {
                CommandHandler.printError("Usage: sidesign dev devices register --name <name> --udid <udid>")
                terminate(code: 1)
            }
            subAction = .register(name: devName, udid: devUDID)
        } else if subArgs.contains("update") || subArgs.contains("rename") {
            var name: String?
            var udid: String?
            var idx = 0
            while idx < subArgs.count {
                if (subArgs[idx] == "--name" || subArgs[idx] == "-n") && idx + 1 < subArgs.count { name = subArgs[idx + 1]; idx += 1 }
                if (subArgs[idx] == "--udid" || subArgs[idx] == "-u" || subArgs[idx] == "--id" || subArgs[idx] == "-i") && idx + 1 < subArgs.count { udid = subArgs[idx + 1]; idx += 1 }
                idx += 1
            }
            guard let name = name, let udid = udid else {
                CommandHandler.printError("Usage: sidesign dev devices update --udid <udid> --name <new_name>")
                terminate(code: 1)
            }
            subAction = .update(name: name, udid: udid)
        } else if subArgs.contains("disable") {
            var udid: String?
            var idx = 0
            while idx < subArgs.count {
                if (subArgs[idx] == "--udid" || subArgs[idx] == "-u" || subArgs[idx] == "--id" || subArgs[idx] == "-i") && idx + 1 < subArgs.count { udid = subArgs[idx + 1]; idx += 1 }
                idx += 1
            }
            guard let udid = udid else {
                CommandHandler.printError("Usage: sidesign dev devices disable --udid <udid>")
                terminate(code: 1)
            }
            subAction = .disable(udid: udid)
        } else if subArgs.contains("delete") || subArgs.contains("remove") || subArgs.contains("rm") {
            var udid: String?
            var idx = 0
            while idx < subArgs.count {
                if (subArgs[idx] == "--udid" || subArgs[idx] == "-u" || subArgs[idx] == "--id" || subArgs[idx] == "-i") && idx + 1 < subArgs.count { udid = subArgs[idx + 1]; idx += 1 }
                idx += 1
            }
            guard let udid = udid else {
                CommandHandler.printError("Usage: sidesign dev devices delete --udid <udid>")
                terminate(code: 1)
            }
            subAction = .delete(udid: udid)
        } else {
            subAction = .list
        }
        return .devices(PortalDeviceOptions(action: subAction, portalOptions: portalOpts))
    }

    if action == "certs" {
        let subAction: PortalCertOptions.Action
        if subArgs.contains("create") || subArgs.contains("add") {
            var csrPath: String?
            var outPath: String?
            var idx = 0
            while idx < subArgs.count {
                if (subArgs[idx] == "--csr" || subArgs[idx] == "-c") && idx + 1 < subArgs.count { csrPath = subArgs[idx + 1]; idx += 1 }
                if (subArgs[idx] == "--output" || subArgs[idx] == "-o") && idx + 1 < subArgs.count { outPath = subArgs[idx + 1]; idx += 1 }
                idx += 1
            }
            subAction = .create(csrPath: csrPath, outPath: outPath)
        } else if subArgs.contains("revoke") || subArgs.contains("rm") || subArgs.contains("delete") {
            var certID: String?
            var idx = 0
            while idx < subArgs.count {
                if (subArgs[idx] == "--id" || subArgs[idx] == "-i") && idx + 1 < subArgs.count { certID = subArgs[idx + 1]; idx += 1 }
                idx += 1
            }
            guard let cID = certID else {
                CommandHandler.printError("Usage: sidesign dev certs revoke --id <cert_serial_or_id>")
                terminate(code: 1)
            }
            subAction = .revoke(certID: cID)
        } else {
            subAction = .list
        }
        return .certs(PortalCertOptions(action: subAction, portalOptions: portalOpts))
    }

    if action == "appids" {
        let subAction: PortalAppIDOptions.Action
        if subArgs.contains("register") || subArgs.contains("create") || subArgs.contains("add") {
            var name: String?
            var bundleID: String?
            var idx = 0
            while idx < subArgs.count {
                if (subArgs[idx] == "--name" || subArgs[idx] == "-n") && idx + 1 < subArgs.count { name = subArgs[idx + 1]; idx += 1 }
                if (subArgs[idx] == "--bundle-id" || subArgs[idx] == "-b" || subArgs[idx] == "-i") && idx + 1 < subArgs.count { bundleID = subArgs[idx + 1]; idx += 1 }
                idx += 1
            }
            guard let name = name, let bundleID = bundleID else {
                CommandHandler.printError("Usage: sidesign dev appids register --name <name> --bundle-id <bundle_id>")
                terminate(code: 1)
            }
            subAction = .register(name: name, bundleID: bundleID)
        } else if subArgs.contains("delete") || subArgs.contains("rm") || subArgs.contains("remove") {
            var targetID: String?
            var idx = 0
            while idx < subArgs.count {
                if (subArgs[idx] == "--id" || subArgs[idx] == "-i") && idx + 1 < subArgs.count { targetID = subArgs[idx + 1]; idx += 1 }
                idx += 1
            }
            guard let targetID = targetID else {
                CommandHandler.printError("Usage: sidesign dev appids delete --id <app_id>")
                terminate(code: 1)
            }
            subAction = .delete(targetID: targetID)
        } else {
            subAction = .list
        }
        return .appIDs(PortalAppIDOptions(action: subAction, portalOptions: portalOpts))
    }

    if action == "appgroups" {
        let subAction: PortalAppGroupOptions.Action
        if subArgs.contains("create") || subArgs.contains("add") {
            var name: String?
            var groupID: String?
            var idx = 0
            while idx < subArgs.count {
                if (subArgs[idx] == "--name" || subArgs[idx] == "-n") && idx + 1 < subArgs.count { name = subArgs[idx + 1]; idx += 1 }
                if (subArgs[idx] == "--group-id" || subArgs[idx] == "-g" || subArgs[idx] == "-id") && idx + 1 < subArgs.count { groupID = subArgs[idx + 1]; idx += 1 }
                idx += 1
            }
            guard let name = name, let groupID = groupID else {
                CommandHandler.printError("Usage: sidesign dev appgroups create --name <name> --group-id <group_id>")
                terminate(code: 1)
            }
            subAction = .create(name: name, groupID: groupID)
        } else if subArgs.contains("assign") {
            var appIDStr: String?
            var groupIDStr: String?
            var idx = 0
            while idx < subArgs.count {
                if (subArgs[idx] == "--app-id" || subArgs[idx] == "-a" || subArgs[idx] == "-aid") && idx + 1 < subArgs.count { appIDStr = subArgs[idx + 1]; idx += 1 }
                if (subArgs[idx] == "--group-id" || subArgs[idx] == "-g" || subArgs[idx] == "-gid") && idx + 1 < subArgs.count { groupIDStr = subArgs[idx + 1]; idx += 1 }
                idx += 1
            }
            guard let appIDStr = appIDStr, let groupIDStr = groupIDStr else {
                CommandHandler.printError("Usage: sidesign dev appgroups assign --app-id <app_id> --group-id <group_id>")
                terminate(code: 1)
            }
            subAction = .assign(appID: appIDStr, groupID: groupIDStr)
        } else if subArgs.contains("update") || subArgs.contains("rename") {
            var name: String?
            var groupIDStr: String?
            var idx = 0
            while idx < subArgs.count {
                if (subArgs[idx] == "--name" || subArgs[idx] == "-n") && idx + 1 < subArgs.count { name = subArgs[idx + 1]; idx += 1 }
                if (subArgs[idx] == "--id" || subArgs[idx] == "--group-id" || subArgs[idx] == "-g" || subArgs[idx] == "-id") && idx + 1 < subArgs.count { groupIDStr = subArgs[idx + 1]; idx += 1 }
                idx += 1
            }
            guard let name = name, let groupIDStr = groupIDStr else {
                CommandHandler.printError("Usage: sidesign dev appgroups update --id <group_id> --name <new_name>")
                terminate(code: 1)
            }
            subAction = .update(name: name, groupID: groupIDStr)
        } else if subArgs.contains("delete") || subArgs.contains("remove") || subArgs.contains("rm") {
            var groupIDStr: String?
            var idx = 0
            while idx < subArgs.count {
                if (subArgs[idx] == "--id" || subArgs[idx] == "--group-id" || subArgs[idx] == "-g" || subArgs[idx] == "-id") && idx + 1 < subArgs.count {
                    groupIDStr = subArgs[idx + 1]
                    idx += 1
                }
                idx += 1
            }
            guard let groupIDStr = groupIDStr else {
                CommandHandler.printError("Usage: sidesign dev appgroups delete --id <group_id>")
                terminate(code: 1)
            }
            subAction = .delete(groupID: groupIDStr)
        } else {
            subAction = .list
        }
        return .appGroups(PortalAppGroupOptions(action: subAction, portalOptions: portalOpts))
    }

    if action == "profiles" {
        let subAction: PortalProfileOptions.Action
        if subArgs.contains("download") || subArgs.contains("fetch") {
            var bundleIDStr: String?
            var outputPath: String?
            var idx = 0
            while idx < subArgs.count {
                if (subArgs[idx] == "--bundle-id" || subArgs[idx] == "-b" || subArgs[idx] == "-i") && idx + 1 < subArgs.count { bundleIDStr = subArgs[idx + 1]; idx += 1 }
                if (subArgs[idx] == "--output" || subArgs[idx] == "-o") && idx + 1 < subArgs.count { outputPath = subArgs[idx + 1]; idx += 1 }
                idx += 1
            }
            guard let bundleID = bundleIDStr else {
                CommandHandler.printError("Usage: sidesign dev profiles download --bundle-id <bundle_id> [--output <path>]")
                terminate(code: 1)
            }
            subAction = .download(bundleID: bundleID, outputPath: outputPath)
        } else if subArgs.contains("delete") || subArgs.contains("rm") || subArgs.contains("remove") {
            var profileID: String?
            var idx = 0
            while idx < subArgs.count {
                if (subArgs[idx] == "--id" || subArgs[idx] == "-i") && idx + 1 < subArgs.count { profileID = subArgs[idx + 1]; idx += 1 }
                idx += 1
            }
            guard let profID = profileID else {
                CommandHandler.printError("Usage: sidesign dev profiles delete --id <profile_id_or_uuid>")
                terminate(code: 1)
            }
            subAction = .delete(profileID: profID)
        } else {
            subAction = .list
        }
        return .profiles(PortalProfileOptions(action: subAction, portalOptions: portalOpts))
    }

    CommandHandler.printError("Unknown dev subcommand: \(action)")
    exit(1)
}

let rawArgs = Array(CommandLine.arguments.dropFirst())

if rawArgs.isEmpty || rawArgs.contains("-h") || rawArgs.contains("--help") || rawArgs.contains("help") {
    printUsage()
    exit(0)
}

if rawArgs.contains("--verbose") || rawArgs.contains("-v") || rawArgs.contains("-vv") || rawArgs.contains("--debug") || rawArgs.contains("-d") {
    SideSignLogging.setLogging(true)
}

print()
defer { print() }

let nonGlobalArgs = rawArgs.filter { !["-v", "--verbose", "-vv", "--debug", "-d"].contains($0) }
guard let command = nonGlobalArgs.first else {
    printUsage()
    exit(0)
}
let subArgs = Array(nonGlobalArgs.dropFirst())

do {
    switch command {
    case "sign", "-s", "--sign":
        let ctx = parseSignContext(args: subArgs)
        try await CommandHandler.handleSign(context: ctx)
    case "verify":
        let ctx = parseVerifyContext(args: subArgs)
        try CommandHandler.handleVerify(context: ctx)
    case "display", "inspect", "-d", "--display":
        let ctx = parseInspectContext(args: subArgs)
        try CommandHandler.handleDisplay(context: ctx)
    case "profile":
        let ctx = parseProfileContext(args: subArgs)
        try CommandHandler.handleProfile(context: ctx)
    case "extensions":
        let ctx = parseExtensionsContext(args: subArgs)
        try CommandHandler.handleExtensions(context: ctx)
    case "archive":
        let ctx = parseArchiveContext(args: subArgs)
        try CommandHandler.handleArchive(context: ctx)
    case "dev", "developer", "portal", "auth":
        let req = parsePortalRequestContext(args: subArgs)
        try await CommandHandler.handlePortal(request: req)
    case "p12":
        let ctx = parseP12Context(args: subArgs)
        try CommandHandler.handleP12(context: ctx)
    case "csr":
        let ctx = parseCSRContext(args: subArgs)
        try CommandHandler.handleCSR(context: ctx)
    case "anisette":
        let ctx = parseAnisetteContext(args: subArgs)
        try await CommandHandler.handleAnisette(context: ctx)
    case "remove-signature", "--remove-signature":
        let ctx = RemoveSignatureContext(targetPath: subArgs.first ?? "")
        guard !ctx.targetPath.isEmpty else {
            CommandHandler.printError("Usage: sidesign remove-signature <path_to_binary_or_bundle>")
            terminate(code: 1)
        }
        try CommandHandler.handleRemoveSignature(context: ctx)
    default:
        if FileManager.default.fileExists(atPath: command) {
            let ctx = parseSignContext(args: [command] + subArgs)
            try await CommandHandler.handleSign(context: ctx)
        } else {
            CommandHandler.printError("Unknown command '\(command)'.")
            printUsage()
            terminate(code: 1)
        }
    }
} catch {
    CommandHandler.printError(error.localizedDescription)
    exit(1)
}
