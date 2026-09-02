//
//  SecureInput.swift
//  SideSign
//
//  Created by Magesh K on 02/09/26.
//  Copyright © 2026 SideStore. All rights reserved.
//

import Foundation

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(Android)
import Android
#elseif os(Windows)
import WinSDK
#endif

enum SecureInput {
    static func readPassword(prompt: String, emptyLineBefore: Bool = true, emptyLineAfter: Bool = true) -> String? {
        if emptyLineBefore { print() }
        #if canImport(Darwin) || os(Linux) || os(Android)
        if let passCStr = getpass(prompt) {
            let passStr = String(cString: passCStr)
            if emptyLineAfter { print() }
            return passStr
        }
        #elseif os(Windows)
        let hStdin = GetStdHandle(STD_INPUT_HANDLE)
        var origMode: DWORD = 0
        if GetConsoleMode(hStdin, &origMode) {
            SetConsoleMode(hStdin, origMode & ~DWORD(ENABLE_ECHO_INPUT))
            defer { SetConsoleMode(hStdin, origMode) }
            print(prompt, terminator: "")
            fflush(nil)
            let input = readLine(strippingNewline: true)
            print()
            if emptyLineAfter { print() }
            return input
        }
        #endif
        print(prompt, terminator: "")
        fflush(nil)
        let input = readLine(strippingNewline: true)
        if emptyLineAfter { print() }
        return input
    }
}
