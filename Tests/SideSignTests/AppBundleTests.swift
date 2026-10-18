import Foundation
import Testing
@testable import SideSign

@Suite("App Bundle Extension Discovery Tests")
struct AppBundleTests {

    @Test
    func discoversExtensionsFromBothDirectoriesAndSkipsInvalidEntries() throws {
        let fixture = try BundleFixture()
        defer { fixture.remove() }

        try fixture.addBundle(named: "Plugin.appex", in: "PlugIns", identifier: "com.example.plugin")
        try fixture.addBundle(named: "Extension.appex", in: "Extensions", identifier: "com.example.extension")
        try fixture.addBundle(named: "Uppercase.APPEX", in: "Extensions", identifier: "com.example.uppercase")
        try fixture.addBundle(named: ".Hidden.appex", in: "Extensions", identifier: "com.example.hidden")
        try fixture.addBundle(named: "Invalid.appex", in: "Extensions", identifier: nil)
        try fixture.addBundle(named: "NotAnExtension.bundle", in: "Extensions", identifier: "com.example.bundle")
        try fixture.addFile(named: "File.appex", in: "Extensions")
        try fixture.addBundle(named: "NestedChild.appex", in: "Extensions/Nested", identifier: "com.example.nested")

        let app = try #require(AppBundle(fileURL: fixture.appURL))
        let discovered = app.appExtensions

        #expect(Set(discovered.map(\.bundleIdentifier)) == [
            "com.example.extension",
            "com.example.plugin",
            "com.example.uppercase"
        ])
        #expect(app.allAppBundles.map(\.bundleIdentifier) == [
            "com.example.app",
            "com.example.extension",
            "com.example.plugin",
            "com.example.uppercase"
        ])
        #expect(app.appBundle(withBundleIdentifier: "com.example.plugin")?.fileURL.lastPathComponent == "Plugin.appex")
        #expect(app.appBundle(withBundleIdentifier: "com.example.extension")?.fileURL.lastPathComponent == "Extension.appex")
        #expect(app.appBundle(withBundleIdentifier: "com.example.nested") == nil)
        #expect(app.appBundle(withBundleIdentifier: "com.example.app")?.fileURL == fixture.appURL)
    }

    @Test
    func discoversExtensionsWhenPlugInsDirectoryIsMissing() throws {
        let fixture = try BundleFixture()
        defer { fixture.remove() }
        try fixture.addBundle(named: "Extension.appex", in: "Extensions", identifier: "com.example.extension")

        let app = try #require(AppBundle(fileURL: fixture.appURL))

        #expect(app.appExtensions.map(\.bundleIdentifier) == ["com.example.extension"])
    }

    @Test
    func discoversExtensionsWhenExtensionsDirectoryIsMissing() throws {
        let fixture = try BundleFixture()
        defer { fixture.remove() }
        try fixture.addBundle(named: "Plugin.appex", in: "PlugIns", identifier: "com.example.plugin")

        let app = try #require(AppBundle(fileURL: fixture.appURL))

        #expect(app.appExtensions.map(\.bundleIdentifier) == ["com.example.plugin"])
    }

    @Test
    func returnsNoExtensionsWhenNeitherDirectoryExists() throws {
        let fixture = try BundleFixture()
        defer { fixture.remove() }

        let app = try #require(AppBundle(fileURL: fixture.appURL))

        #expect(app.appExtensions.isEmpty)
    }

    @Test(arguments: ["PlugIns", "Extensions"])
    func unreadableDirectoryDoesNotHideOtherDirectory(unreadableDirectory: String) throws {
        let fixture = try BundleFixture()
        defer { fixture.remove() }
        let readableDirectory = unreadableDirectory == "PlugIns" ? "Extensions" : "PlugIns"
        try fixture.addFile(named: unreadableDirectory, in: nil)
        try fixture.addBundle(named: "Extension.appex", in: readableDirectory, identifier: "com.example.extension")

        let app = try #require(AppBundle(fileURL: fixture.appURL))

        #expect(app.appExtensions.map(\.bundleIdentifier) == ["com.example.extension"])
    }
}

private struct BundleFixture {
    let rootURL: URL
    let appURL: URL

    init() throws {
        let fileManager = FileManager.default
        rootURL = fileManager.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        appURL = rootURL.appendingPathComponent("Sample.app")
        try fileManager.createDirectory(at: appURL, withIntermediateDirectories: true)
        try Self.writeInfoPlist(to: appURL, identifier: "com.example.app")
    }

    func addBundle(named name: String, in directoryName: String, identifier: String?) throws {
        let directoryURL = appURL.appendingPathComponent(directoryName)
        let bundleURL = directoryURL.appendingPathComponent(name)
        try FileManager.default.createDirectory(at: bundleURL, withIntermediateDirectories: true)
        if let identifier {
            try Self.writeInfoPlist(to: bundleURL, identifier: identifier)
        }
    }

    func addFile(named name: String, in directoryName: String?) throws {
        let directoryURL = directoryName.map { appURL.appendingPathComponent($0) } ?? appURL
        try FileManager.default.createDirectory(at: directoryURL, withIntermediateDirectories: true)
        try Data().write(to: directoryURL.appendingPathComponent(name))
    }

    func remove() {
        try? FileManager.default.removeItem(at: rootURL)
    }

    private static func writeInfoPlist(to bundleURL: URL, identifier: String) throws {
        let plist: [String: Any] = [
            "CFBundleIdentifier": identifier,
            "CFBundleName": bundleURL.deletingPathExtension().lastPathComponent,
            "CFBundleShortVersionString": "1.0",
            "CFBundleVersion": "1"
        ]
        let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        try data.write(to: bundleURL.appendingPathComponent("Info.plist"))
    }
}
