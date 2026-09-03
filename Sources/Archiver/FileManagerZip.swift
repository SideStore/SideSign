//
//  FileManagerZip.swift
//  SideSign
//
//  Created by Magesh K on 28/08/26.
//  Copyright © 2026 SideStore. All rights reserved.
//

import Foundation

extension FileManager {

    // POSIX file type flags (external attributes in ZIP catalog are shifted by 16 bits)
    private static let S_IFREG: UInt32 = 0o100000 // Regular file
    private static let S_IFDIR: UInt32 = 0o040000 // Directory

    // Default permissions when not defined in the source archive
    private static let defaultFilePermissions: UInt32 = 0o644
    private static let defaultDirPermissions: UInt32  = 0o755

    func unzipArchive(at archiveURL: URL, to directoryURL: URL, progress: Progress? = nil) throws {
        verboseLog("[SideSign] FileManager.unzipArchive started for archive: \(archiveURL.path) to: \(directoryURL.path)")
        let archive = try Archive.Reader.open(at: archiveURL)
        try archive.goToFirstFile()

        repeat {

            let name = try archive.currentFilename()

            if name.hasPrefix("__MACOSX") {
                verboseLog("[SideSign] FileManager.unzipArchive: skipping __MACOSX entry: \(name)")
                continue
            }

            let outputURL =
                directoryURL.appendingPathComponent(name)

            let externalAttributes = archive.currentFileExternalAttributes()
            var permissions = (externalAttributes >> 16) & 0x01FF
            if permissions == 0 {
                permissions = name.hasSuffix("/") ? Self.defaultDirPermissions : Self.defaultFilePermissions
            }

            if name.hasSuffix("/") {
                verboseLog("[SideSign] FileManager.unzipArchive: creating directory: \(outputURL.path)")
                try createDirectory(
                    at: outputURL,
                    withIntermediateDirectories: true,
                    attributes: [.posixPermissions: NSNumber(value: permissions)]
                )
                continue
            }

            verboseLog("[SideSign] FileManager.unzipArchive: extracting file: \(outputURL.path)")
            try createDirectory(
                at: outputURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )

            try archive.extractCurrentFile(to: outputURL)

            if permissions != 0 {
                try setAttributes([.posixPermissions: NSNumber(value: permissions)], ofItemAtPath: outputURL.path)
            }

            if let attributes = try? attributesOfItem(atPath: outputURL.path),
               let size = attributes[.size] as? NSNumber {
                progress?.completedUnitCount += size.int64Value
            }

        } while archive.goToNextFile()
        verboseLog("[SideSign] FileManager.unzipArchive completed successfully")
    }

    public func unzipAppBundle(at ipaURL: URL, to directoryURL: URL) throws -> URL {
        verboseLog("[SideSign] FileManager.unzipAppBundle starting for: \(ipaURL.path) to: \(directoryURL.path)")
        try unzipArchive(at: ipaURL, to: directoryURL)

        let payload = directoryURL.appendingPathComponent("Payload")
        let contents = try contentsOfDirectory(atPath: payload.path)
        verboseLog("[SideSign] FileManager.unzipAppBundle: checking payload folder contents: \(contents)")

        for file in contents where file.lowercased().hasSuffix(".app") {

            let appURL = payload.appendingPathComponent(file)
            let outputURL = directoryURL.appendingPathComponent(file)

            verboseLog("[SideSign] FileManager.unzipAppBundle: moving app bundle from \(appURL.path) to \(outputURL.path)")
            try moveItem(at: appURL, to: outputURL)
            try removeItem(at: payload)

            verboseLog("[SideSign] FileManager.unzipAppBundle completed. Return app path: \(outputURL.path)")
            return outputURL
        }

        verboseLog("[SideSign] FileManager.unzipAppBundle error: missing app bundle inside Payload folder of \(ipaURL.path)")
        throw Archive.Error.missingAppBundle(ipaURL)
    }

    public func unzipAppBundle(at ipaURL: URL, toDirectory directoryURL: URL) throws -> URL {
        return try self.unzipAppBundle(at: ipaURL, to: directoryURL)
    }

    public struct CompressionLevel: RawRepresentable, ExpressibleByIntegerLiteral, Sendable, Equatable {
        public let rawValue: Int16

        public init(rawValue: Int16) {
            self.rawValue = rawValue
        }

        public init(integerLiteral value: Int16) {
            self.rawValue = value
        }

        public static let none: CompressionLevel      = 0
        public static let fastest: CompressionLevel   = 1
        public static let standard: CompressionLevel  = 6
        public static let maximum: CompressionLevel   = 9
    }

    public func zipAppBundle(at appBundleURL: URL, compressionLevel: CompressionLevel = .none) throws -> URL {
        verboseLog("[SideSign] FileManager.zipAppBundle starting for: \(appBundleURL.path)")
        let name = appBundleURL.deletingPathExtension().lastPathComponent

        let ipaURL = appBundleURL
            .deletingLastPathComponent()
            .appendingPathComponent("\(name).ipa")

        if fileExists(atPath: ipaURL.path) {
            verboseLog("[SideSign] FileManager.zipAppBundle: removing existing ipa at \(ipaURL.path)")
            try removeItem(at: ipaURL)
        }

        let writer = try Archive.Writer.create(at: ipaURL)
        writer.setCompressLevel(compressionLevel.rawValue)


        let canonicalBundleURL = appBundleURL.resolvingSymlinksInPath()
        let basePath = canonicalBundleURL.path.hasSuffix("/") ? canonicalBundleURL.path : canonicalBundleURL.path + "/"

        let enumerator = self.enumerator(
            at: canonicalBundleURL,
            includingPropertiesForKeys: [.isDirectoryKey]
        )!

        verboseLog("[SideSign] FileManager.zipAppBundle: enumerating contents of app bundle...")
        for case let fileURL as URL in enumerator {
            let canonicalFileURL = fileURL.resolvingSymlinksInPath()
            let isDir = (try? canonicalFileURL.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true

            let fullPath = canonicalFileURL.path
            guard fullPath.hasPrefix(basePath) else { continue }
            let relative = String(fullPath.dropFirst(basePath.count))

            let zipPath = "Payload/\(appBundleURL.lastPathComponent)/\(relative)" + (isDir ? "/" : "")

            let attributes = try self.attributesOfItem(atPath: canonicalFileURL.path)
            let posixPermissions = (attributes[.posixPermissions] as? NSNumber)?.uint32Value ?? (isDir ? Self.defaultDirPermissions : Self.defaultFilePermissions)

            verboseLog("[SideSign] FileManager.zipAppBundle: writing zip entry relative: \(relative), path in zip: \(zipPath), isDir: \(isDir), permissions: \(String(format: "%0o", posixPermissions))")

            if isDir {
                let permissions = Self.S_IFDIR + posixPermissions
                try writer.writeFile(path: zipPath, data: nil, permissions: permissions)
            } else {
                try writer.addFile(at: canonicalFileURL, pathInZip: zipPath)
            }
        }

        verboseLog("[SideSign] FileManager.zipAppBundle completed. Packaged ipa path: \(ipaURL.path)")
        return ipaURL
    }
}
