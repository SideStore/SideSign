//
//  SideSign.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
import CodeSignKit
import GSACryptoKit

public enum SideSign {
    public static var isLoggingEnabled: Bool {
        return Logging.isLoggingEnabled
    }

    public static func setLogging(_ enabled: Bool) {
        Logging.setLogging(enabled)
    }
}

internal extension Data {
    func hexEncodedString() -> String {
        map { String(format: "%02hhx", $0) }.joined()
    }
}
