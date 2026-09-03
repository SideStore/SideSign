//
//  SideSignTests.swift
//  SideSignTests
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Testing
@testable import SideSign
import CodeSignKit
import GSACryptoKit

@Suite("SideSign Core Tests")
struct SideSignTests {

    @Test
    func deviceInitializationAndFiltering() throws {
        let device = Device(name: "My iPhone", identifier: "00008030-001234567890ABCD", type: .iPhone)
        #expect(device.name == "My iPhone")
        #expect(device.identifier == "00008030-001234567890ABCD")
        #expect(device.type == .iPhone)
    }

    @Test
    func certificateRequestCSRGeneration() throws {
        let request = try CertificateRequest(machineName: "TestMac")
        #expect(!request.csrData.isEmpty)
        #expect(!request.privateKey.isEmpty)
        #expect(request.machineName == "TestMac")
    }

    @Test
    func developerPortalSingleton() throws {
        let portal = DeveloperPortal.shared
        #expect(portal.baseURL == Constants.URLs.developerServicesBase)
        #expect(portal.servicesBaseURL == Constants.URLs.developerServicesV1Base)
    }

    @Test
    func archiveStoreRoundtrip() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let zipURL = tempDir.appendingPathComponent("test_store.zip")
        let writer = try Archive.Writer.create(at: zipURL)
        writer.setCompressLevel(0) // Store

        let testContent = "Hello from SideSign Archive Store!".data(using: .utf8)!
        try writer.writeFile(path: "test.txt", data: testContent, permissions: 0o644)
        try writer.writeFile(path: "bin/tool", data: testContent, permissions: 0o755)
        try writer.close()

        let reader = try Archive.Reader.open(at: zipURL)
        let entries = try reader.entries()
        #expect(entries.count == 2)

        let filenames = Set(entries.map(\.filename))
        #expect(filenames.contains("test.txt"))
        #expect(filenames.contains("bin/tool"))

        for entry in entries {
            if entry.filename == "bin/tool" {
                #expect(entry.posixPermissions == 0o755)
            } else if entry.filename == "test.txt" {
                #expect(entry.posixPermissions == 0o644)
            }
        }

        try reader.goToFirstFile()
        let readData = try reader.readCurrentFile()
        #expect(readData == testContent)
    }

    @Test
    func archiveDeflateRoundtrip() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let zipURL = tempDir.appendingPathComponent("test_deflate.zip")
        let writer = try Archive.Writer.create(at: zipURL)
        writer.setCompressLevel(1) // Deflate fastest

        let repeatedText = String(repeating: "SideStore high-performance libdeflate compression test ", count: 100)
        let testContent = repeatedText.data(using: .utf8)!
        try writer.writeFile(path: "compressed.txt", data: testContent, permissions: 0o644)
        try writer.close()

        let reader = try Archive.Reader.open(at: zipURL)
        let entries = try reader.entries()
        #expect(entries.count == 1)
        #expect(entries.first?.filename == "compressed.txt")
        #expect(entries.first?.compressionMethod == 8)

        try reader.goToFirstFile()
        let decompressed = try reader.readCurrentFile()
        #expect(decompressed == testContent)
    }
}
