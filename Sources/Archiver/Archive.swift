//
//  Archive.swift
//  SideSign
//
//  Created by Magesh K on 28/08/26.
//  Copyright © 2026 SideStore. All rights reserved.
//

import Foundation
import libdeflate

#if canImport(Darwin)
import Darwin
#elseif canImport(Android)
import Android
#elseif canImport(Bionic)
import Bionic
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

public enum Archive {

    public struct Entry: Sendable, Hashable {
        public let filename: String
        public let uncompressedSize: Int64
        public let compressedSize: Int64
        public let crc: UInt32
        public let externalAttributes: UInt32
        public let compressionMethod: UInt16
        public let localHeaderOffset: UInt64

        public var isDirectory: Bool {
            return filename.hasSuffix("/") || ((externalAttributes >> 16) & 0o040000 != 0)
        }

        public var posixPermissions: UInt32 {
            let perms = (externalAttributes >> 16) & 0o777
            if perms != 0 { return perms }
            return isDirectory ? 0o755 : 0o644
        }

        public init(
            filename: String,
            uncompressedSize: Int64,
            compressedSize: Int64,
            crc: UInt32,
            externalAttributes: UInt32,
            compressionMethod: UInt16 = 0,
            localHeaderOffset: UInt64 = 0
        ) {
            self.filename = filename
            self.uncompressedSize = uncompressedSize
            self.compressedSize = compressedSize
            self.crc = crc
            self.externalAttributes = externalAttributes
            self.compressionMethod = compressionMethod
            self.localHeaderOffset = localHeaderOffset
        }
    }

    public final class Reader {
        private let fileURL: URL
        private let fileHandle: FileHandle
        private let parsedEntries: [Entry]
        private var currentIndex: Int = 0

        private init(fileURL: URL, fileHandle: FileHandle, entries: [Entry]) {
            self.fileURL = fileURL
            self.fileHandle = fileHandle
            self.parsedEntries = entries
            self.currentIndex = 0
        }

        deinit {
            try? fileHandle.close()
        }

        public static func open(at url: URL) throws -> Reader {
            verboseLog("[SideSign] Archive.Reader.open(at: \(url.path)) started")
            guard FileManager.default.fileExists(atPath: url.path) else {
                debugLog("[SideSign] Archive.Reader.open failed: file not found at \(url.path)")
                throw Archive.Error.fileNotFound(url)
            }

            guard let handle = try? FileHandle(forReadingFrom: url) else {
                throw Archive.Error.readFailed(url)
            }

            let entries = try parseCentralDirectory(handle: handle, fileURL: url)
            verboseLog("[SideSign] Archive.Reader.open succeeded with \(entries.count) entries")
            return Reader(fileURL: url, fileHandle: handle, entries: entries)
        }

        public func goToFirstFile() throws {
            verboseLog("[SideSign] Archive.Reader.goToFirstFile called")
            guard !parsedEntries.isEmpty else {
                throw Archive.Error.readFailed(fileURL)
            }
            currentIndex = 0
        }

        public func goToNextFile() -> Bool {
            let nextIndex = currentIndex + 1
            let hasNext = nextIndex < parsedEntries.count
            if hasNext {
                currentIndex = nextIndex
            }
            verboseLog("[SideSign] Archive.Reader.goToNextFile called. Has next file: \(hasNext)")
            return hasNext
        }

        public func currentFilename() throws -> String {
            guard currentIndex < parsedEntries.count else {
                throw Archive.Error.readFailed(fileURL)
            }
            let filename = parsedEntries[currentIndex].filename
            verboseLog("[SideSign] Archive.Reader.currentFilename retrieved: \(filename)")
            return filename
        }

        public func currentFileExternalAttributes() -> UInt32 {
            guard currentIndex < parsedEntries.count else { return 0 }
            return parsedEntries[currentIndex].externalAttributes
        }

        public func currentEntry() throws -> Entry {
            guard currentIndex < parsedEntries.count else {
                throw Archive.Error.readFailed(fileURL)
            }
            return parsedEntries[currentIndex]
        }

        public func entries() throws -> [Entry] {
            return parsedEntries
        }

        public func readCurrentFile() throws -> Data {
            guard currentIndex < parsedEntries.count else {
                throw Archive.Error.readFailed(fileURL)
            }
            let entry = parsedEntries[currentIndex]
            verboseLog("[SideSign] Archive.Reader.readCurrentFile started for \(entry.filename)")
            return try extractData(for: entry)
        }

        public func extractCurrentFile(to destinationURL: URL) throws {
            guard currentIndex < parsedEntries.count else {
                throw Archive.Error.readFailed(fileURL)
            }
            let entry = parsedEntries[currentIndex]
            verboseLog("[SideSign] Archive.Reader.extractCurrentFile started: \(entry.filename) -> \(destinationURL.path)")

            let fileManager = FileManager.default
            if entry.isDirectory {
                try fileManager.createDirectory(at: destinationURL, withIntermediateDirectories: true)
                applyPermissions(entry.posixPermissions, to: destinationURL)
                verboseLog("[SideSign] Archive.Reader.extractCurrentFile created directory")
                return
            }

            let parentDir = destinationURL.deletingLastPathComponent()
            try fileManager.createDirectory(at: parentDir, withIntermediateDirectories: true)

            let data = try extractData(for: entry)
            try data.write(to: destinationURL, options: .atomic)
            applyPermissions(entry.posixPermissions, to: destinationURL)
            verboseLog("[SideSign] Archive.Reader.extractCurrentFile completed successfully")
        }

        private func extractData(for entry: Entry) throws -> Data {
            if entry.isDirectory || entry.uncompressedSize == 0 {
                return Data()
            }

            try fileHandle.seek(toOffset: entry.localHeaderOffset)
            guard let localHeaderData = try fileHandle.read(upToCount: 30), localHeaderData.count == 30 else {
                throw Archive.Error.readFailed(fileURL)
            }

            let magic = localHeaderData.readUInt32LE(at: 0)
            guard magic == 0x04034b50 else {
                throw Archive.Error.corruptArchive(fileURL)
            }

            let nameLen = Int(localHeaderData.readUInt16LE(at: 26))
            let extraLen = Int(localHeaderData.readUInt16LE(at: 28))
            let skipOffset = entry.localHeaderOffset + 30 + UInt64(nameLen + extraLen)

            try fileHandle.seek(toOffset: skipOffset)
            guard let rawData = try fileHandle.read(upToCount: Int(entry.compressedSize)),
                  rawData.count == Int(entry.compressedSize) else {
                throw Archive.Error.readFailed(fileURL)
            }

            if entry.compressionMethod == 0 {
                if entry.crc != 0 {
                    let computedCRC = rawData.withUnsafeBytes { rawBuf in
                        libdeflate_crc32(0, rawBuf.baseAddress, rawBuf.count)
                    }
                    guard computedCRC == entry.crc else {
                        throw Archive.Error.corruptArchive(fileURL)
                    }
                }
                return rawData
            } else if entry.compressionMethod == 8 {
                guard let decompressor = libdeflate_alloc_decompressor() else {
                    throw Archive.Error.readFailed(fileURL)
                }
                defer { libdeflate_free_decompressor(decompressor) }

                var uncompressed = Data(count: Int(entry.uncompressedSize))
                var actualOutBytes: Int = 0

                let result = uncompressed.withUnsafeMutableBytes { outBuf in
                    rawData.withUnsafeBytes { inBuf in
                        libdeflate_deflate_decompress(
                            decompressor,
                            inBuf.baseAddress,
                            inBuf.count,
                            outBuf.baseAddress,
                            outBuf.count,
                            &actualOutBytes
                        )
                    }
                }

                guard result == LIBDEFLATE_SUCCESS, actualOutBytes == Int(entry.uncompressedSize) else {
                    debugLog("[SideSign] Archive.Reader decompress failed with libdeflate result: \(result.rawValue)")
                    throw Archive.Error.corruptArchive(fileURL)
                }

                if entry.crc != 0 {
                    let computedCRC = uncompressed.withUnsafeBytes { outBuf in
                        libdeflate_crc32(0, outBuf.baseAddress, outBuf.count)
                    }
                    guard computedCRC == entry.crc else {
                        debugLog("[SideSign] Archive.Reader CRC mismatch for \(entry.filename): expected \(entry.crc), got \(computedCRC)")
                        throw Archive.Error.corruptArchive(fileURL)
                    }
                }
                return uncompressed
            } else {
                throw Archive.Error.corruptArchive(fileURL)
            }
        }

        private static func parseCentralDirectory(handle: FileHandle, fileURL: URL) throws -> [Entry] {
            let fileSize = try handle.seekToEnd()
            guard fileSize >= 22 else {
                throw Archive.Error.corruptArchive(fileURL)
            }

            let searchLen = min(fileSize, 65536 + 22)
            let searchOffset = fileSize - searchLen
            try handle.seek(toOffset: searchOffset)
            guard let searchData = try handle.read(upToCount: Int(searchLen)), !searchData.isEmpty else {
                throw Archive.Error.readFailed(fileURL)
            }

            var eocdOffsetInSearch: Int? = nil
            for i in stride(from: searchData.count - 22, through: 0, by: -1) {
                if searchData.readUInt32LE(at: i) == 0x06054b50 {
                    eocdOffsetInSearch = i
                    break
                }
            }

            guard let eocdPos = eocdOffsetInSearch else {
                throw Archive.Error.corruptArchive(fileURL)
            }

            let totalEntries = searchData.readUInt16LE(at: eocdPos + 10)
            let cdSize = UInt64(searchData.readUInt32LE(at: eocdPos + 12))
            let cdOffset = UInt64(searchData.readUInt32LE(at: eocdPos + 16))

            guard cdOffset + cdSize <= fileSize else {
                throw Archive.Error.corruptArchive(fileURL)
            }

            try handle.seek(toOffset: cdOffset)
            guard let cdData = try handle.read(upToCount: Int(cdSize)), cdData.count == Int(cdSize) else {
                throw Archive.Error.readFailed(fileURL)
            }

            var entries: [Entry] = []
            var offset = 0
            for _ in 0..<totalEntries {
                guard offset + 46 <= cdData.count else { break }
                let magic = cdData.readUInt32LE(at: offset)
                guard magic == 0x02014b50 else { break }

                let method = cdData.readUInt16LE(at: offset + 10)
                let crc = cdData.readUInt32LE(at: offset + 16)
                let compSize = Int64(cdData.readUInt32LE(at: offset + 20))
                let uncompSize = Int64(cdData.readUInt32LE(at: offset + 24))
                let nameLen = Int(cdData.readUInt16LE(at: offset + 28))
                let extraLen = Int(cdData.readUInt16LE(at: offset + 30))
                let commentLen = Int(cdData.readUInt16LE(at: offset + 32))
                let externalAttr = cdData.readUInt32LE(at: offset + 38)
                let localOffset = UInt64(cdData.readUInt32LE(at: offset + 42))

                let nameStart = offset + 46
                guard nameStart + nameLen <= cdData.count else { break }
                let nameBytes = cdData.subdata(in: nameStart..<(nameStart + nameLen))
                let filename = String(data: nameBytes, encoding: .utf8) ?? String(decoding: nameBytes, as: UTF8.self)

                entries.append(Entry(
                    filename: filename,
                    uncompressedSize: uncompSize,
                    compressedSize: compSize,
                    crc: crc,
                    externalAttributes: externalAttr,
                    compressionMethod: method,
                    localHeaderOffset: localOffset
                ))

                offset = nameStart + nameLen + extraLen + commentLen
            }

            return entries
        }

        private func applyPermissions(_ permissions: UInt32, to url: URL) {
            #if !os(Windows)
            #if canImport(Darwin) || canImport(Android) || canImport(Bionic) || canImport(Glibc) || canImport(Musl)
            _ = chmod(url.path, mode_t(permissions))
            #endif
            try? FileManager.default.setAttributes([.posixPermissions: NSNumber(value: permissions)], ofItemAtPath: url.path)
            #endif
        }
    }

    public final class Writer {
        private let destinationURL: URL
        private let fileHandle: FileHandle
        private var compressLevel: Int16 = 0
        private var currentOffset: UInt64 = 0
        private var centralDirectoryEntries: [CentralDirectoryRecord] = []
        private var isClosed: Bool = false

        private struct CentralDirectoryRecord {
            let filename: String
            let compressionMethod: UInt16
            let modTime: UInt16
            let modDate: UInt16
            let crc32: UInt32
            let compressedSize: UInt32
            let uncompressedSize: UInt32
            let externalAttributes: UInt32
            let localHeaderOffset: UInt64
        }

        private init(destinationURL: URL, fileHandle: FileHandle) {
            self.destinationURL = destinationURL
            self.fileHandle = fileHandle
            self.currentOffset = 0
            self.compressLevel = 0
        }

        deinit {
            if !isClosed {
                try? close()
            }
        }

        public static func create(at url: URL) throws -> Writer {
            verboseLog("[SideSign] Archive.Writer.create(at: \(url.path)) started")
            let fileManager = FileManager.default
            if fileManager.fileExists(atPath: url.path) {
                try? fileManager.removeItem(at: url)
            }
            guard fileManager.createFile(atPath: url.path, contents: nil) else {
                throw Archive.Error.writeFailed(url)
            }
            guard let handle = try? FileHandle(forWritingTo: url) else {
                throw Archive.Error.writeFailed(url)
            }
            verboseLog("[SideSign] Archive.Writer.create succeeded")
            return Writer(destinationURL: url, fileHandle: handle)
        }

        public func setCompressLevel(_ level: Int16) {
            self.compressLevel = level
        }

        public func addFile(at fileURL: URL, pathInZip: String) throws {
            verboseLog("[SideSign] Archive.Writer.addFile started: \(fileURL.path) -> \(pathInZip)")
            let data = try Data(contentsOf: fileURL)
            let attributes = (try? FileManager.default.attributesOfItem(atPath: fileURL.path)) ?? [:]
            let posixPerms = (attributes[.posixPermissions] as? NSNumber)?.uint32Value ?? 0o644
            let modDate = (attributes[.modificationDate] as? Date) ?? Date()

            try writeEntry(
                path: pathInZip,
                data: data,
                permissions: posixPerms,
                isDir: false,
                date: modDate
            )
            verboseLog("[SideSign] Archive.Writer.addFile completed successfully")
        }

        public func writeFile(path: String, data: Data?, permissions: UInt32) throws {
            verboseLog("[SideSign] Archive.Writer.writeFile started for internal path: '\(path)'")
            let isDir = path.hasSuffix("/") || (data == nil)
            try writeEntry(
                path: path,
                data: data ?? Data(),
                permissions: permissions,
                isDir: isDir,
                date: Date()
            )
            verboseLog("[SideSign] Archive.Writer.writeFile completed successfully")
        }

        private func writeEntry(
            path: String,
            data: Data,
            permissions: UInt32,
            isDir: Bool,
            date: Date
        ) throws {
            guard !isClosed else { throw Archive.Error.writeFailed(destinationURL) }

            let (dosDate, dosTime) = Self.dosDateTime(from: date)
            let nameData = Data(path.utf8)
            let uncompressedSize = UInt32(data.count)

            let crc: UInt32
            if isDir || data.isEmpty {
                crc = 0
            } else {
                crc = data.withUnsafeBytes { rawBuf in
                    libdeflate_crc32(0, rawBuf.baseAddress, rawBuf.count)
                }
            }

            var method: UInt16 = 0 // Store
            var payload = data

            if !isDir && !data.isEmpty && compressLevel > 0 {
                if let compressor = libdeflate_alloc_compressor(Int32(compressLevel)) {
                    defer { libdeflate_free_compressor(compressor) }
                    let maxBound = libdeflate_deflate_compress_bound(compressor, data.count)
                    var outBuf = [UInt8](repeating: 0, count: maxBound)

                    let compressedLen = data.withUnsafeBytes { inBuf in
                        libdeflate_deflate_compress(
                            compressor,
                            inBuf.baseAddress,
                            inBuf.count,
                            &outBuf,
                            outBuf.count
                        )
                    }

                    if compressedLen > 0 && compressedLen < data.count {
                        method = 8 // Deflate
                        payload = Data(outBuf.prefix(compressedLen))
                    }
                }
            }

            let compressedSize = UInt32(payload.count)
            let localHeaderOffset = currentOffset

            // Local File Header (30 bytes + filename)
            var localHeader = Data(count: 30)
            localHeader.writeUInt32LE(0x04034b50, at: 0)
            localHeader.writeUInt16LE(20, at: 4) // Version needed
            localHeader.writeUInt16LE(0x0800, at: 6) // UTF-8
            localHeader.writeUInt16LE(method, at: 8)
            localHeader.writeUInt16LE(dosTime, at: 10)
            localHeader.writeUInt16LE(dosDate, at: 12)
            localHeader.writeUInt32LE(crc, at: 14)
            localHeader.writeUInt32LE(compressedSize, at: 18)
            localHeader.writeUInt32LE(uncompressedSize, at: 22)
            localHeader.writeUInt16LE(UInt16(nameData.count), at: 26)
            localHeader.writeUInt16LE(0, at: 28) // Extra field length

            try fileHandle.write(contentsOf: localHeader)
            try fileHandle.write(contentsOf: nameData)
            if !payload.isEmpty {
                try fileHandle.write(contentsOf: payload)
            }

            currentOffset += UInt64(30 + nameData.count + payload.count)

            let externalAttr: UInt32
            if isDir {
                externalAttr = (0o040000 | (permissions & 0o777)) << 16
            } else {
                externalAttr = (0o100000 | (permissions & 0o777)) << 16
            }

            centralDirectoryEntries.append(CentralDirectoryRecord(
                filename: path,
                compressionMethod: method,
                modTime: dosTime,
                modDate: dosDate,
                crc32: crc,
                compressedSize: compressedSize,
                uncompressedSize: uncompressedSize,
                externalAttributes: externalAttr,
                localHeaderOffset: localHeaderOffset
            ))
        }

        public func close() throws {
            guard !isClosed else { return }
            isClosed = true

            let cdStartOffset = currentOffset
            for record in centralDirectoryEntries {
                let nameData = Data(record.filename.utf8)

                var cdHeader = Data(count: 46)
                cdHeader.writeUInt32LE(0x02014b50, at: 0)
                cdHeader.writeUInt16LE(0x031e, at: 4) // Version made by: UNIX 3.0
                cdHeader.writeUInt16LE(20, at: 6) // Version needed: 2.0
                cdHeader.writeUInt16LE(0x0800, at: 8) // UTF-8
                cdHeader.writeUInt16LE(record.compressionMethod, at: 10)
                cdHeader.writeUInt16LE(record.modTime, at: 12)
                cdHeader.writeUInt16LE(record.modDate, at: 14)
                cdHeader.writeUInt32LE(record.crc32, at: 16)
                cdHeader.writeUInt32LE(record.compressedSize, at: 20)
                cdHeader.writeUInt32LE(record.uncompressedSize, at: 24)
                cdHeader.writeUInt16LE(UInt16(nameData.count), at: 28)
                cdHeader.writeUInt16LE(0, at: 30) // Extra field length
                cdHeader.writeUInt16LE(0, at: 32) // File comment length
                cdHeader.writeUInt16LE(0, at: 34) // Disk number start
                cdHeader.writeUInt16LE(0, at: 36) // Internal attributes
                cdHeader.writeUInt32LE(record.externalAttributes, at: 38)
                cdHeader.writeUInt32LE(UInt32(record.localHeaderOffset), at: 42)

                try fileHandle.write(contentsOf: cdHeader)
                try fileHandle.write(contentsOf: nameData)
                currentOffset += UInt64(46 + nameData.count)
            }

            let cdSize = UInt32(currentOffset - cdStartOffset)
            let totalRecords = UInt16(centralDirectoryEntries.count)

            // End of Central Directory (EOCD: 22 bytes)
            var eocd = Data(count: 22)
            eocd.writeUInt32LE(0x06054b50, at: 0)
            eocd.writeUInt16LE(0, at: 4) // Disk number
            eocd.writeUInt16LE(0, at: 6) // Disk with CD
            eocd.writeUInt16LE(totalRecords, at: 8) // Entries this disk
            eocd.writeUInt16LE(totalRecords, at: 10) // Total entries
            eocd.writeUInt32LE(cdSize, at: 12) // CD size
            eocd.writeUInt32LE(UInt32(cdStartOffset), at: 16) // CD start offset
            eocd.writeUInt16LE(0, at: 20) // Comment length

            try fileHandle.write(contentsOf: eocd)
            try fileHandle.synchronize()
            try fileHandle.close()
            verboseLog("[SideSign] Archive.Writer finalized with \(totalRecords) entries")
        }

        private static func dosDateTime(from date: Date) -> (UInt16, UInt16) {
            let calendar = Calendar(identifier: .gregorian)
            let comps = calendar.dateComponents([.year, .month, .day, .hour, .minute, .second], from: date)
            let year = max(1980, comps.year ?? 1980) - 1980
            let month = comps.month ?? 1
            let day = comps.day ?? 1
            let hour = comps.hour ?? 0
            let minute = comps.minute ?? 0
            let second = comps.second ?? 0

            let dosDate = UInt16(((year & 0x7F) << 9) | ((month & 0x0F) << 5) | (day & 0x1F))
            let dosTime = UInt16(((hour & 0x1F) << 11) | ((minute & 0x3F) << 5) | ((second / 2) & 0x1F))
            return (dosDate, dosTime)
        }
    }

    public enum Error: Swift.Error, LocalizedError {
        case fileNotFound(URL)
        case corruptArchive(URL)
        case readFailed(URL)
        case writeFailed(URL)
        case missingAppBundle(URL)

        public var errorDescription: String? {
            switch self {
            case .fileNotFound(let url):
                return "File not found: \(url.lastPathComponent)"
            case .corruptArchive(let url):
                return "Archive appears to be corrupt: \(url.lastPathComponent)"
            case .readFailed(let url):
                return "Failed to read archive: \(url.lastPathComponent)"
            case .writeFailed(let url):
                return "Failed to write archive: \(url.lastPathComponent)"
            case .missingAppBundle(let url):
                return "No .app bundle found inside \(url.lastPathComponent)"
            }
        }
    }
}

private extension Data {
    func readUInt16LE(at offset: Int) -> UInt16 {
        return self.withUnsafeBytes { raw in
            raw.load(fromByteOffset: offset, as: UInt16.self).littleEndian
        }
    }

    func readUInt32LE(at offset: Int) -> UInt32 {
        return self.withUnsafeBytes { raw in
            raw.load(fromByteOffset: offset, as: UInt32.self).littleEndian
        }
    }

    mutating func writeUInt16LE(_ value: UInt16, at offset: Int) {
        var v = value.littleEndian
        Swift.withUnsafeBytes(of: &v) { valBuf in
            self.replaceSubrange(offset..<(offset + 2), with: valBuf)
        }
    }

    mutating func writeUInt32LE(_ value: UInt32, at offset: Int) {
        var v = value.littleEndian
        Swift.withUnsafeBytes(of: &v) { valBuf in
            self.replaceSubrange(offset..<(offset + 4), with: valBuf)
        }
    }
}
