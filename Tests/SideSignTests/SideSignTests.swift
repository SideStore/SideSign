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
}
