//
//  Archive.swift
//  SideSign
//
//  Created by Magesh K on 28/08/26.
//  Copyright © 2026 SideStore. All rights reserved.
//

import Foundation
import minizip_ng

public enum Archive {

    public typealias ReaderHandle = UnsafeMutableRawPointer
    public typealias WriterHandle = UnsafeMutableRawPointer
    public typealias FileInfo = mz_zip_file
    public typealias FileInfoPointer = UnsafeMutablePointer<mz_zip_file>

    public struct Entry: Sendable, Hashable {
        public let filename: String
        public let uncompressedSize: Int64
        public let compressedSize: Int64
        public let crc: UInt32
        public let externalAttributes: UInt32

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
            externalAttributes: UInt32
        ) {
            self.filename = filename
            self.uncompressedSize = uncompressedSize
            self.compressedSize = compressedSize
            self.crc = crc
            self.externalAttributes = externalAttributes
        }
    }

    public final class Reader {

        private let handle: ReaderHandle

        private init(_ handle: ReaderHandle) {
            self.handle = handle
        }

        deinit {
            var r: ReaderHandle? = handle
            mz_zip_reader_close(handle)
            mz_zip_reader_delete(&r)
        }

        public static func open(at url: URL) throws -> Reader {
            verboseLog("[SideSign] Archive.Reader.open(at: \(url.path)) started")
            guard FileManager.default.fileExists(atPath: url.path) else {
                debugLog("[SideSign] Archive.Reader.open failed: file not found at \(url.path)")
                throw Archive.Error.fileNotFound(url)
            }
            guard let reader = mz_zip_reader_create() else {
                throw Archive.Error.corruptArchive(url)
            }
            let err = url.path.withCString {
                mz_zip_reader_open_file(reader, $0)
            }
            guard err == MZ_OK else {
                debugLog("[SideSign] Archive.Reader.open failed with minizip-ng error: \(err)")
                var r: ReaderHandle? = reader
                mz_zip_reader_delete(&r)
                if err == MZ_OPEN_ERROR {
                    throw Archive.Error.readFailed(url)
                }
                throw Archive.Error.corruptArchive(url)
            }
            verboseLog("[SideSign] Archive.Reader.open succeeded")
            return Reader(reader)
        }

        public func goToFirstFile() throws {
            verboseLog("[SideSign] Archive.Reader.goToFirstFile called")
            guard mz_zip_reader_goto_first_entry(handle) == MZ_OK else {
                debugLog("[SideSign] Archive.Reader.goToFirstFile failed")
                throw Archive.Error.readFailed(.init(fileURLWithPath: ""))
            }
        }

        public func goToNextFile() -> Bool {
            let hasNext = mz_zip_reader_goto_next_entry(handle) == MZ_OK
            verboseLog("[SideSign] Archive.Reader.goToNextFile called. Has next file: \(hasNext)")
            return hasNext
        }

        public func currentFilename() throws -> String {
            var fileInfo: FileInfoPointer? = nil
            guard mz_zip_reader_entry_get_info(handle, &fileInfo) == MZ_OK,
                  let info = fileInfo?.pointee,
                  let cName = info.filename else {
                debugLog("[SideSign] Archive.Reader.currentFilename failed to get info from minizip-ng")
                throw Archive.Error.readFailed(.init(fileURLWithPath: ""))
            }

            let filename = String(cString: cName)
            verboseLog("[SideSign] Archive.Reader.currentFilename retrieved: \(filename)")
            return filename
        }

        public func currentFileExternalAttributes() -> UInt32 {
            var fileInfo: FileInfoPointer? = nil
            if mz_zip_reader_entry_get_info(handle, &fileInfo) == MZ_OK,
               let info = fileInfo?.pointee {
                return info.external_fa
            }
            return 0
        }

        public func currentEntry() throws -> Entry {
            var fileInfo: FileInfoPointer? = nil
            guard mz_zip_reader_entry_get_info(handle, &fileInfo) == MZ_OK,
                  let info = fileInfo?.pointee else {
                debugLog("[SideSign] Archive.Reader.currentEntry failed to read entry info")
                throw Archive.Error.readFailed(.init(fileURLWithPath: ""))
            }

            let filename = info.filename != nil ? String(cString: info.filename) : ""
            return Entry(
                filename: filename,
                uncompressedSize: info.uncompressed_size,
                compressedSize: info.compressed_size,
                crc: info.crc,
                externalAttributes: info.external_fa
            )
        }

        public func entries() throws -> [Entry] {
            var result: [Entry] = []
            try goToFirstFile()
            repeat {
                let entry = try currentEntry()
                result.append(entry)
            } while goToNextFile()
            return result
        }

        public func readCurrentFile() throws -> Data {
            verboseLog("[SideSign] Archive.Reader.readCurrentFile started")
            guard mz_zip_reader_entry_open(handle) == MZ_OK else {
                debugLog("[SideSign] Archive.Reader.readCurrentFile failed: mz_zip_reader_entry_open returned error")
                throw Archive.Error.readFailed(.init(fileURLWithPath: ""))
            }

            defer {
                mz_zip_reader_entry_close(handle)
            }

            var result = Data()
            var buffer = [UInt8](repeating: 0, count: 32_768)

            while true {
                let read = buffer.withUnsafeMutableBytes { rawBuf in
                    mz_zip_reader_entry_read(handle, rawBuf.baseAddress, Int32(rawBuf.count))
                }

                if read < 0 {
                    debugLog("[SideSign] Archive.Reader.readCurrentFile failed: mz_zip_reader_entry_read returned error code \(read)")
                    throw Archive.Error.readFailed(.init(fileURLWithPath: ""))
                }

                if read == 0 { break }

                result.append(buffer, count: Int(read))
            }

            verboseLog("[SideSign] Archive.Reader.readCurrentFile completed. Read size: \(result.count) bytes")
            return result
        }

        public func extractCurrentFile(to destinationURL: URL) throws {
            verboseLog("[SideSign] Archive.Reader.extractCurrentFile(to: \(destinationURL.path)) started")
            let result = destinationURL.path.withCString {
                mz_zip_reader_entry_save_file(handle, $0)
            }
            guard result == MZ_OK else {
                debugLog("[SideSign] Archive.Reader.extractCurrentFile failed: mz_zip_reader_entry_save_file returned error")
                throw Archive.Error.readFailed(destinationURL)
            }
            verboseLog("[SideSign] Archive.Reader.extractCurrentFile completed successfully")
        }
    }

    public final class Writer {

        private let handle: WriterHandle

        private init(_ handle: WriterHandle) {
            self.handle = handle
        }

        deinit {
            verboseLog("[SideSign] Archive.Writer.deinit closing zip handle")
            var w: WriterHandle? = handle
            mz_zip_writer_close(handle)
            mz_zip_writer_delete(&w)
        }

        public static func create(at url: URL) throws -> Writer {
            verboseLog("[SideSign] Archive.Writer.create(at: \(url.path)) started")
            guard let writer = mz_zip_writer_create() else {
                throw Archive.Error.writeFailed(url)
            }
            let err = url.path.withCString {
                mz_zip_writer_open_file(writer, $0, 0, 0)
            }
            guard err == MZ_OK else {
                debugLog("[SideSign] Archive.Writer.create failed with minizip-ng error: \(err)")
                var w: WriterHandle? = writer
                mz_zip_writer_delete(&w)
                throw Archive.Error.writeFailed(url)
            }
            verboseLog("[SideSign] Archive.Writer.create succeeded")
            return Writer(writer)
        }

        public func setCompressLevel(_ level: Int16) {
            mz_zip_writer_set_compress_level(handle, level)
        }

        public func addFile(at fileURL: URL, pathInZip: String) throws {
            verboseLog("[SideSign] Archive.Writer.addFile started for file: \(fileURL.path) -> \(pathInZip)")
            let ok = fileURL.path.withCString { sourcePath in
                pathInZip.withCString { zipPath in
                    mz_zip_writer_add_file(handle, sourcePath, zipPath) == MZ_OK
                }
            }
            guard ok else {
                debugLog("[SideSign] Archive.Writer.addFile failed for \(fileURL.path)")
                throw Archive.Error.writeFailed(fileURL)
            }
            verboseLog("[SideSign] Archive.Writer.addFile completed successfully")
        }

        public func writeFile(path: String, data: Data?, permissions: UInt32) throws {
            verboseLog("[SideSign] Archive.Writer.writeFile started for internal path: '\(path)', data size: \(data?.count ?? 0) bytes, permissions: \(String(format: "%0o", permissions))")

            var fileInfo = FileInfo()
            fileInfo.external_fa = permissions << 16
            fileInfo.compression_method = UInt16(MZ_COMPRESS_METHOD_DEFLATE)

            let openOK = path.withCString { cPath in
                fileInfo.filename = cPath
                return mz_zip_writer_entry_open(handle, &fileInfo) == MZ_OK
            }

            guard openOK else {
                debugLog("[SideSign] Archive.Writer.writeFile failed: mz_zip_writer_entry_open returned error")
                throw Archive.Error.writeFailed(.init(fileURLWithPath: path))
            }

            defer {
                mz_zip_writer_entry_close(handle)
            }

            guard let data else {
                verboseLog("[SideSign] Archive.Writer.writeFile completed: no data to write")
                return
            }

            let ok = data.withUnsafeBytes { rawBuf in
                let written = mz_zip_writer_entry_write(
                    handle,
                    rawBuf.baseAddress,
                    Int32(data.count)
                )
                return written == Int32(data.count)
            }

            guard ok else {
                debugLog("[SideSign] Archive.Writer.writeFile failed: mz_zip_writer_entry_write returned error")
                throw Archive.Error.writeFailed(.init(fileURLWithPath: path))
            }

            verboseLog("[SideSign] Archive.Writer.writeFile completed successfully")
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
