//
//  PortalCommandsParser.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideStore. All rights reserved.
//

import Foundation
import SideSign

public enum PortalCommandsParser {
    public static let usageText = """
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
      sidesign dev auth-devices list / remove <device_id> / purge-anisette [--session <path>]
      sidesign dev certs list / create / revoke --id <id> [--session <path>]
      sidesign dev appids list / register --name <name> --bundle-id <id> / delete --id <id> [--session <path>]
      sidesign dev appgroups list / create --name <name> --group-id <id> / assign --app-id <id> --group-id <id> [--session <path>]
      sidesign dev profiles list / download --bundle-id <id> [--output <path>] / delete --id <id> [--session <path>]
    """

    private static let actions: [String: [String]] = [
        "list":         ["list", "sessions", "ls"],
        "selectTeam":   ["select-team", "set-team"],
        "selectTeamID": ["select-team-id", "set-team-id"],
        "logout":       ["logout"],
        "status":       ["status"],
        "relogin":      ["relogin"],
        "login":        ["login"],
        "teams":        ["teams"],
        "devices":      ["devices"],
        "authDevices":  ["auth-devices", "authdevices", "account-devices"],
        "certs":        ["certs"],
        "appids":       ["appids"],
        "appgroups":    ["appgroups"],
        "profiles":     ["profiles"]
    ]

    private static let portalFlags: [String: [String]] = [
        "appleID":          ["--apple-id", "-u", "-a"],
        "password":         ["--password", "-p", "-pwd", "-w"],
        "session":          ["--session", "--session-file", "-s"],
        "usingTeam":        ["--using-team", "--select-team", "-t"],
        "usingTeamID":      ["--using-team-id", "--select-team-id", "--use-team", "-tid"],
        "encryptPassword":  ["--encrypt-password", "-ep"],
        "machinePassword":  ["--machine-password", "--adi-password", "-mpwd"],
        "machinePath":      ["--machine-path", "--adi-path", "-mp"],
        "anisetteURL":      ["--anisette-url", "--anisette", "--server", "-srv"],
        "localAnisette":    ["--local-anisette", "--local-adi", "--local", "-l"],
        "oda":              ["--oda", "-oda"],
        "forceODA":         ["--force-oda", "--force-download-oda"],
        "source":           ["--source", "--list", "-src"],
        "selectServer":     ["--select-server", "-sel"],
        "failover":         ["--failover", "--auto-failover", "-f"],
        "startIndex":       ["--start-index", "-idx"],
        "strict":           ["--strict", "-st"]
    ]

    private static let deviceFlags: [String: [String]] = [
        "name":             ["--name", "-n"],
        "udid":             ["--udid", "-u", "--id", "-i"]
    ]

    private static let certFlags: [String: [String]] = [
        "csr":              ["--csr", "-c"],
        "output":           ["--output", "-o"],
        "id":               ["--id", "-i"]
    ]

    private static let appIDFlags: [String: [String]] = [
        "name":             ["--name", "-n"],
        "bundleID":         ["--bundle-id", "-b", "-i"],
        "id":               ["--id", "-i"]
    ]

    private static let appGroupFlags: [String: [String]] = [
        "name":             ["--name", "-n"],
        "groupID":          ["--group-id", "-g", "-id", "-gid"],
        "appID":            ["--app-id", "-a", "-aid"],
        "id":               ["--id", "-i"]
    ]

    private static let profileFlags: [String: [String]] = [
        "bundleID":         ["--bundle-id", "-b", "-i"],
        "output":           ["--output", "-o"],
        "id":               ["--id", "-i"]
    ]

    public static func parseOptions(args: [String]) throws -> (options: PortalOptions, appleID: String?) {
        let flags = portalFlags
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
        func nextVal() -> String? {
            guard i + 1 < args.count, !args[i + 1].hasPrefix("-") else { return nil }
            i += 1
            return args[i]
        }

        var forceODA = false

        while i < args.count {
            switch args[i] {
            case flags["appleID"]:          appleID            = nextVal()
            case flags["password"]:         password           = nextVal()
            case flags["session"]:          sessionPath        = nextVal()
            case flags["usingTeam"]:        teamID             = try CommandHandler.resolveTeamIDFromIndex(nextVal())
            case flags["usingTeamID"]:      teamID             = try nextVal().map { try CommandHandler.validateAndResolveTeamID($0) }
            case flags["encryptPassword"]:  encryptPassword    = nextVal()
            case flags["machinePassword"]:  deviceDataPassword = nextVal()
            case flags["machinePath"]:      deviceDataPath     = nextVal()
            case flags["anisetteURL"]:      anisetteURL        = nextVal()
            case flags["localAnisette"]:    localAnisetteDir   = nextVal()
            case flags["oda"]:              odaURL             = nextVal()
            case flags["forceODA"]:         forceODA           = true
            case flags["source"]:           sourceURLStr       = nextVal()
            case flags["selectServer"]:     selectServer       = true
            case flags["failover"]:         enableFailover     = true
            case flags["startIndex"]:       startIndex         = nextVal().flatMap(Int.init) ?? 0
            case flags["strict"]:           strict             = true
            default:                        break
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
            forceODA: forceODA,
            selectServer: selectServer,
            strict: strict,
            sourceURLStr: sourceURLStr,
            enableFailover: enableFailover,
            startIndex: startIndex
        )
        return (opts, appleID)
    }

    public static func parseDevices(subArgs: [String], opts: PortalOptions) throws -> PortalRequestContext {
        let flags = deviceFlags
        let subAction: PortalDeviceOptions.Action

        var idx = 0
        func nextVal() -> String? {
            guard idx + 1 < subArgs.count, !subArgs[idx + 1].hasPrefix("-") else { return nil }
            idx += 1
            return subArgs[idx]
        }

        if subArgs.contains("register") || subArgs.contains("add") {
            var name: String?
            var udid: String?
            while idx < subArgs.count {
                switch subArgs[idx] {
                case flags["name"]: name = nextVal()
                case flags["udid"]: udid = nextVal()
                default:            break
                }
                idx += 1
            }
            guard let devName = name, let devUDID = udid else {
                throw CLIError.missingRequiredArgument("Usage: sidesign dev devices register --name <name> --udid <udid>")
            }
            subAction = .register(name: devName, udid: devUDID)
        } else if subArgs.contains("update") || subArgs.contains("rename") {
            var name: String?
            var udid: String?
            while idx < subArgs.count {
                switch subArgs[idx] {
                case flags["name"]: name = nextVal()
                case flags["udid"]: udid = nextVal()
                default:            break
                }
                idx += 1
            }
            guard let name = name, let udid = udid else {
                throw CLIError.missingRequiredArgument("Usage: sidesign dev devices update --udid <udid> --name <new_name>")
            }
            subAction = .update(name: name, udid: udid)
        } else if subArgs.contains("disable") {
            var udid: String?
            while idx < subArgs.count {
                switch subArgs[idx] {
                case flags["udid"]: udid = nextVal()
                default:            break
                }
                idx += 1
            }
            guard let udid = udid else {
                throw CLIError.missingRequiredArgument("Usage: sidesign dev devices disable --udid <udid>")
            }
            subAction = .disable(udid: udid)
        } else if subArgs.contains("delete") || subArgs.contains("remove") || subArgs.contains("rm") {
            var udid: String?
            while idx < subArgs.count {
                switch subArgs[idx] {
                case flags["udid"]: udid = nextVal()
                default:            break
                }
                idx += 1
            }
            guard let udid = udid else {
                throw CLIError.missingRequiredArgument("Usage: sidesign dev devices delete --udid <udid>")
            }
            subAction = .delete(udid: udid)
        } else {
            subAction = .list
        }
        return .devices(PortalDeviceOptions(action: subAction, portalOptions: opts))
    }

    public static func parseCerts(subArgs: [String], opts: PortalOptions) throws -> PortalRequestContext {
        let flags = certFlags
        let subAction: PortalCertOptions.Action

        var idx = 0
        func nextVal() -> String? {
            guard idx + 1 < subArgs.count, !subArgs[idx + 1].hasPrefix("-") else { return nil }
            idx += 1
            return subArgs[idx]
        }

        if subArgs.contains("create") || subArgs.contains("add") {
            var csrPath: String?
            var outPath: String?
            while idx < subArgs.count {
                switch subArgs[idx] {
                case flags["csr"]:      csrPath = nextVal()
                case flags["output"]:   outPath = nextVal()
                default:                break
                }
                idx += 1
            }
            subAction = .create(csrPath: csrPath, outPath: outPath)
        } else if subArgs.contains("revoke") || subArgs.contains("rm") || subArgs.contains("delete") {
            var certID: String?
            while idx < subArgs.count {
                switch subArgs[idx] {
                case flags["id"]:   certID = nextVal()
                default:            break
                }
                idx += 1
            }
            guard let cID = certID else {
                throw CLIError.missingRequiredArgument("Usage: sidesign dev certs revoke --id <cert_serial_or_id>")
            }
            subAction = .revoke(certID: cID)
        } else {
            subAction = .list
        }
        return .certs(PortalCertOptions(action: subAction, portalOptions: opts))
    }

    public static func parseAppIDs(subArgs: [String], opts: PortalOptions) throws -> PortalRequestContext {
        let flags = appIDFlags
        let subAction: PortalAppIDOptions.Action

        var idx = 0
        func nextVal() -> String? {
            guard idx + 1 < subArgs.count, !subArgs[idx + 1].hasPrefix("-") else { return nil }
            idx += 1
            return subArgs[idx]
        }

        if subArgs.contains("register") || subArgs.contains("create") || subArgs.contains("add") {
            var name: String?
            var bundleID: String?
            while idx < subArgs.count {
                switch subArgs[idx] {
                case flags["name"]:     name     = nextVal()
                case flags["bundleID"]: bundleID = nextVal()
                default:                break
                }
                idx += 1
            }
            guard let name = name, let bundleID = bundleID else {
                throw CLIError.missingRequiredArgument("Usage: sidesign dev appids register --name <name> --bundle-id <bundle_id>")
            }
            subAction = .register(name: name, bundleID: bundleID)
        } else if subArgs.contains("delete") || subArgs.contains("rm") || subArgs.contains("remove") {
            var targetID: String?
            while idx < subArgs.count {
                switch subArgs[idx] {
                case flags["id"]:   targetID = nextVal()
                default:            break
                }
                idx += 1
            }
            guard let targetID = targetID else {
                throw CLIError.missingRequiredArgument("Usage: sidesign dev appids delete --id <app_id>")
            }
            subAction = .delete(targetID: targetID)
        } else {
            subAction = .list
        }
        return .appIDs(PortalAppIDOptions(action: subAction, portalOptions: opts))
    }

    public static func parseAppGroups(subArgs: [String], opts: PortalOptions) throws -> PortalRequestContext {
        let flags = appGroupFlags
        let subAction: PortalAppGroupOptions.Action

        var idx = 0
        func nextVal() -> String? {
            guard idx + 1 < subArgs.count, !subArgs[idx + 1].hasPrefix("-") else { return nil }
            idx += 1
            return subArgs[idx]
        }

        if subArgs.contains("create") || subArgs.contains("add") {
            var name: String?
            var groupID: String?
            while idx < subArgs.count {
                switch subArgs[idx] {
                case flags["name"]:     name    = nextVal()
                case flags["groupID"]:  groupID = nextVal()
                default:                break
                }
                idx += 1
            }
            guard let name = name, let groupID = groupID else {
                throw CLIError.missingRequiredArgument("Usage: sidesign dev appgroups create --name <name> --group-id <group_id>")
            }
            subAction = .create(name: name, groupID: groupID)
        } else if subArgs.contains("assign") {
            var appIDStr: String?
            var groupIDStr: String?
            while idx < subArgs.count {
                switch subArgs[idx] {
                case flags["appID"]:    appIDStr   = nextVal()
                case flags["groupID"]:  groupIDStr = nextVal()
                default:                break
                }
                idx += 1
            }
            guard let appIDStr = appIDStr, let groupIDStr = groupIDStr else {
                throw CLIError.missingRequiredArgument("Usage: sidesign dev appgroups assign --app-id <app_id> --group-id <group_id>")
            }
            subAction = .assign(appID: appIDStr, groupID: groupIDStr)
        } else if subArgs.contains("update") || subArgs.contains("rename") {
            var name: String?
            var groupIDStr: String?
            while idx < subArgs.count {
                switch subArgs[idx] {
                case flags["name"]:     name       = nextVal()
                case flags["groupID"]:  groupIDStr = nextVal()
                default:                break
                }
                idx += 1
            }
            guard let name = name, let groupIDStr = groupIDStr else {
                throw CLIError.missingRequiredArgument("Usage: sidesign dev appgroups update --id <group_id> --name <new_name>")
            }
            subAction = .update(name: name, groupID: groupIDStr)
        } else if subArgs.contains("delete") || subArgs.contains("remove") || subArgs.contains("rm") {
            var groupIDStr: String?
            while idx < subArgs.count {
                switch subArgs[idx] {
                case flags["groupID"]:  groupIDStr = nextVal()
                default:                break
                }
                idx += 1
            }
            guard let groupIDStr = groupIDStr else {
                throw CLIError.missingRequiredArgument("Usage: sidesign dev appgroups delete --id <group_id>")
            }
            subAction = .delete(groupID: groupIDStr)
        } else {
            subAction = .list
        }
        return .appGroups(PortalAppGroupOptions(action: subAction, portalOptions: opts))
    }

    public static func parseProfiles(subArgs: [String], opts: PortalOptions) throws -> PortalRequestContext {
        let flags = profileFlags
        let subAction: PortalProfileOptions.Action

        var idx = 0
        func nextVal() -> String? {
            guard idx + 1 < subArgs.count, !subArgs[idx + 1].hasPrefix("-") else { return nil }
            idx += 1
            return subArgs[idx]
        }

        if subArgs.contains("download") || subArgs.contains("fetch") {
            var bundleIDStr: String?
            var outputPath: String?
            while idx < subArgs.count {
                switch subArgs[idx] {
                case flags["bundleID"]: bundleIDStr = nextVal()
                case flags["output"]:   outputPath  = nextVal()
                default:                break
                }
                idx += 1
            }
            guard let bundleID = bundleIDStr else {
                throw CLIError.missingRequiredArgument("Usage: sidesign dev profiles download --bundle-id <bundle_id> [--output <path>]")
            }
            subAction = .download(bundleID: bundleID, outputPath: outputPath)
        } else if subArgs.contains("delete") || subArgs.contains("rm") || subArgs.contains("remove") {
            var profileID: String?
            while idx < subArgs.count {
                switch subArgs[idx] {
                case flags["id"]:   profileID = nextVal()
                default:            break
                }
                idx += 1
            }
            guard let profID = profileID else {
                throw CLIError.missingRequiredArgument("Usage: sidesign dev profiles delete --id <profile_id_or_uuid>")
            }
            subAction = .delete(profileID: profID)
        } else {
            subAction = .list
        }
        return .profiles(PortalProfileOptions(action: subAction, portalOptions: opts))
    }

    private static func parseAuthDevices(subArgs: [String], opts: PortalOptions) throws -> PortalRequestContext {
        let cleanArgs = subArgs.filter { !$0.hasPrefix("-") }
        let subAction = cleanArgs.first ?? "list"

        switch subAction {
        case "list", "ls":
            return .authDevices(PortalAuthDeviceOptions(action: .list, portalOptions: opts))
        case "remove", "delete", "rm":
            guard cleanArgs.count > 1 else {
                throw CLIError.missingRequiredArgument("Device ID required to remove (e.g. sidesign auth auth-devices remove <id>)")
            }
            return .authDevices(PortalAuthDeviceOptions(action: .remove(deviceID: cleanArgs[1]), portalOptions: opts))
        case "purge", "purge-anisette", "clear-anisette":
            return .authDevices(PortalAuthDeviceOptions(action: .purgeAnisette, portalOptions: opts))
        default:
            throw CLIError.invalidArgument("Unknown auth-devices subcommand: \(subAction). Supported: list, remove <id>, purge-anisette")
        }
    }

    public static func parse(args: [String]) throws -> PortalRequestContext {
        guard let action = args.first else {
            throw CLIError.missingRequiredArgument(usageText)
        }

        let subArgs = Array(args.dropFirst())
        let (portalOpts, appleID) = try parseOptions(args: subArgs)

        switch action {
        case actions["list"]:
            return .list
        case actions["selectTeam"]:
            return .selectTeam(index: subArgs.first)
        case actions["selectTeamID"]:
            guard let tID = subArgs.first else {
                throw CLIError.missingRequiredArgument("Team ID required (e.g. sidesign dev select-team-id TEAM123456)")
            }
            return .selectTeamID(teamID: tID)
        case actions["logout"]:
            return .logout(sessionPath: portalOpts.sessionPath, teamID: portalOpts.teamID)
        case actions["status"]:
            return .status(sessionPath: portalOpts.sessionPath, password: portalOpts.password, encryptPassword: portalOpts.encryptPassword, teamID: portalOpts.teamID)
        case actions["relogin"]:
            return .relogin(portalOpts)
        case actions["login"]:
            guard let email = appleID else {
                throw CLIError.missingRequiredArgument("Apple ID is required for login (--apple-id <email>).")
            }
            return .login(PortalLoginOptions(appleID: email, portalOptions: portalOpts))
        case actions["teams"]:
            return .teams(portalOpts)
        case actions["devices"]:
            return try parseDevices(subArgs: subArgs, opts: portalOpts)
        case actions["authDevices"]:
            return try parseAuthDevices(subArgs: subArgs, opts: portalOpts)
        case actions["certs"]:
            return try parseCerts(subArgs: subArgs, opts: portalOpts)
        case actions["appids"]:
            return try parseAppIDs(subArgs: subArgs, opts: portalOpts)
        case actions["appgroups"]:
            return try parseAppGroups(subArgs: subArgs, opts: portalOpts)
        case actions["profiles"]:
            return try parseProfiles(subArgs: subArgs, opts: portalOpts)
        default:
            throw CLIError.invalidArgument("Unknown dev subcommand: \(action)\n\n\(usageText)")
        }
    }
}
