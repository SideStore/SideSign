//
//  Logging.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation

public enum Logging {
    public private(set) static var isLoggingEnabled = false

    public static func setLogging(_ enabled: Bool) {
        defer { debugLog("[SideSign] setLogging(\(enabled)) completed") }
        debugLog("[SideSign] setLogging(\(enabled)) invoked")
        isLoggingEnabled = enabled
    }
}

@inline(__always)
private func getTag(level: String) -> String {
    let formatter = DateFormatter()
    formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
    formatter.locale = Locale(identifier: "en_US_POSIX")
    let timestamp = formatter.string(from: Date())
    return "\(timestamp) \(level): "
}

@inline(__always)
public func debugLog(_ text: @autoclosure () -> String) {
    let message = text()
    if !message.isEmpty && message.allSatisfy({ $0 == "\n" || $0 == "\r" }) {
        print(message, terminator: "")
    } else {
        print("\(getTag(level: "[D]"))\(message)")
    }
}

@inline(__always)
public func verboseLog(_ text: @autoclosure () -> String) {
    if Logging.isLoggingEnabled {
        let message = text()
        if !message.isEmpty && message.allSatisfy({ $0 == "\n" || $0 == "\r" }) {
            print(message, terminator: "")
        } else {
            print("\(getTag(level: "[V]"))\(message)")
        }
    }
}

func prettyJSONString(from object: any Sendable) -> String {
    let sanitized = sanitizeForJSON(object)
    if JSONSerialization.isValidJSONObject(sanitized) {
        do {
            let data = try JSONSerialization.data(withJSONObject: sanitized, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
            if let string = String(data: data, encoding: .utf8) {
                return string
            }
        } catch {}
    }
    if let data = object as? Data {
        if let str = String(data: data, encoding: .utf8) {
            return formatPayloadString(str)
        }
        return data.hexEncodedString()
    }
    if let str = object as? String {
        return formatPayloadString(str)
    }
    return "\(object)"
}

func formatPayload(_ data: Data) -> String? {
    if let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) {
        return prettyJSONString(from: plist)
    }
    if let jsonObject = try? JSONSerialization.jsonObject(with: data, options: []) {
        return prettyJSONString(from: jsonObject)
    }
    if let string = String(data: data, encoding: .utf8) {
        return formatPayloadString(string)
    }
    return nil
}

private func formatPayloadString(_ str: String) -> String {
    let trimmed = str.trimmingCharacters(in: .whitespacesAndNewlines)
    if trimmed.hasPrefix("<") {
        return prettyPrintXML(trimmed)
    }
    return trimmed
}

private func prettyPrintXML(_ rawXML: String) -> String {
    let pattern = "(<[^>]+>)|([^<]+)"
    guard let regex = try? NSRegularExpression(pattern: pattern, options: [.dotMatchesLineSeparators]) else {
        return rawXML
    }

    let nsString = rawXML as NSString
    let matches = regex.matches(in: rawXML, options: [], range: NSRange(location: 0, length: nsString.length))

    var result: [String] = []
    var indentLevel = 0

    for match in matches {
        var token = nsString.substring(with: match.range).trimmingCharacters(in: .whitespacesAndNewlines)
        if token.isEmpty { continue }

        // Collapse internal newlines and multiple spaces inside XML tags
        if token.hasPrefix("<") && !token.hasPrefix("<![CDATA[") {
            token = token.replacingOccurrences(of: "\\s+", with: " ", options: .regularExpression)
        }

        if token.hasPrefix("</") {
            indentLevel = max(0, indentLevel - 1)
            let indent = String(repeating: "  ", count: indentLevel)
            result.append("\(indent)\(token)")
        } else if token.hasPrefix("<?") || token.hasPrefix("<!") || token.hasSuffix("/>") {
            let indent = String(repeating: "  ", count: indentLevel)
            result.append("\(indent)\(token)")
        } else if token.hasPrefix("<") {
            let indent = String(repeating: "  ", count: indentLevel)
            result.append("\(indent)\(token)")
            indentLevel += 1
        } else {
            let baseIndent = String(repeating: "  ", count: indentLevel)
            let subLines = token.components(separatedBy: .newlines)
            var cssIndent = 0
            for subLine in subLines {
                let subTrimmed = subLine.trimmingCharacters(in: .whitespaces)
                if subTrimmed.isEmpty { continue }

                if subTrimmed.hasPrefix("}") {
                    cssIndent = max(0, cssIndent - 1)
                }

                let extraIndent = String(repeating: "  ", count: cssIndent)
                result.append("\(baseIndent)\(extraIndent)\(subTrimmed)")

                if subTrimmed.hasSuffix("{") {
                    cssIndent += 1
                }
            }
        }
    }

    return result.joined(separator: "\n")
}

private func sanitizeForJSON(_ object: any Sendable) -> any Sendable {
    if let dict = object as? [String: any Sendable] {
        return dict.mapValues { sanitizeForJSON($0) }
    } else if let array = object as? [any Sendable] {
        return array.map { sanitizeForJSON($0) }
    } else if let date = object as? Date {
        let formatter = ISO8601DateFormatter()
        return formatter.string(from: date)
    } else if let data = object as? Data {
        return data.base64EncodedString()
    } else if let number = object as? NSNumber {
        return number
    } else if let string = object as? String {
        return string
    } else {
        return "\(object)"
    }
}
