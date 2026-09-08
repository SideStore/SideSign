import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Testing
@testable import SideSign

private final class Responses: @unchecked Sendable {
    private let lock = NSLock()
    private var statuses: [Int] = []
    private var sessions: [URLSession] = []
    private var delays: [UInt64] = []
    private var requests: [URLRequest] = []
    private var failure: URLError?

    func reset(_ statuses: [Int], failure: URLError? = nil) {
        lock.lock(); defer { lock.unlock() }
        self.statuses = statuses
        self.failure = failure
        sessions = []; delays = []; requests = []
    }
    func next(_ request: URLRequest) -> (Int, URLError?) {
        lock.lock(); defer { lock.unlock() }
        requests.append(request)
        return (statuses.isEmpty ? 503 : statuses.removeFirst(), failure)
    }
    func session(_ configuration: URLSessionConfiguration) -> URLSession {
        #expect(configuration.urlCache == nil)
        #expect(configuration.httpCookieStorage == nil)
        #expect(configuration.urlCredentialStorage == nil)
        #expect(configuration.requestCachePolicy == .reloadIgnoringLocalCacheData)
        configuration.protocolClasses = [GrandSlamProtocol.self]
        let session = URLSession(configuration: configuration)
        lock.lock(); defer { lock.unlock() }
        sessions.append(session)
        return session
    }
    func delay(_ value: UInt64) {
        lock.lock(); defer { lock.unlock() }
        delays.append(value)
    }
    func verify(attempts: Int, seconds: [UInt64]) {
        lock.lock(); defer { lock.unlock() }
        #expect(sessions.count == attempts)
        #expect(Set(sessions.map(ObjectIdentifier.init)).count == attempts)
        #expect(requests.count == attempts)
        #expect(delays == seconds.map { $0 * 1_000_000_000 })
        #expect(requests.allSatisfy { $0.httpMethod == "POST" })
        #expect(requests.allSatisfy { $0.httpBody == requests.first?.httpBody })
        #expect(requests.allSatisfy { $0.value(forHTTPHeaderField: "User-Agent") == "AuthKit/test" })
    }
}

private final class GrandSlamProtocol: URLProtocol, @unchecked Sendable {
    static let responses = Responses()
    static let plist = Data("""
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict><key>Response</key><dict><key>Status</key><dict><key>ec</key><integer>0</integer></dict></dict></dict></plist>
        """.utf8)

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let (status, failure) = Self.responses.next(request)
        if let failure {
            client?.urlProtocol(self, didFailWithError: failure)
            return
        }
        let html = (500...599).contains(status)
        let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1",
                                       headerFields: ["Content-Type": html ? "text/html" : "text/x-xml-plist"])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: html ? Data("<html>503 Service Temporarily Unavailable</html>".utf8) : Self.plist)
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

@Suite(.serialized)
struct GrandSlamTransportTests {
    private func request() -> URLRequest {
        var request = URLRequest(url: URL(string: "https://gsa.apple.com/grandslam/GsService2")!)
        request.httpMethod = "POST"
        request.httpBody = Data("test auth request".utf8)
        request.setValue("AuthKit/test", forHTTPHeaderField: "User-Agent")
        return request
    }
    private func send() async throws -> (Data, URLResponse) {
        try await GrandSlamTransport.data(for: request(), makeSession: { GrandSlamProtocol.responses.session($0) },
                                         sleep: { GrandSlamProtocol.responses.delay($0) })
    }
    @Test func successfulPlistIsUnchanged() async throws {
        GrandSlamProtocol.responses.reset([200])
        let (data, response) = try await send()
        #expect((response as? HTTPURLResponse)?.statusCode == 200)
        #expect(data == GrandSlamProtocol.plist)
        let plist = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
        #expect(plist?["Response"] != nil)
        GrandSlamProtocol.responses.verify(attempts: 1, seconds: [])
    }
    @Test(arguments: [1, 2, 4]) func html503ThenSuccess(failures: Int) async throws {
        GrandSlamProtocol.responses.reset(Array(repeating: 503, count: failures) + [200])
        let (data, response) = try await send()
        #expect(data == GrandSlamProtocol.plist)
        #expect((response as? HTTPURLResponse)?.statusCode == 200)
        GrandSlamProtocol.responses.verify(attempts: failures + 1, seconds: Array([1, 2, 4, 8].prefix(failures)))
    }
    @Test(arguments: [500, 502, 503, 504, 599]) func boundedServerFailure(status: Int) async throws {
        GrandSlamProtocol.responses.reset(Array(repeating: status, count: 6))
        do {
            _ = try await send()
            Issue.record("Expected HTTP server error")
        } catch {
            let error = error as NSError
            #expect(error.domain == NSURLErrorDomain)
            #expect(error.code == NSURLErrorBadServerResponse)
            #expect(error.userInfo["HTTPStatusCode"] as? Int == status)
            #expect(error.userInfo["ContentType"] as? String == "text/html")
            #expect(error.localizedDescription.contains("HTTP \(status)"))
            #expect(error.localizedDescription.contains("5 attempts"))
            #expect(!error.localizedDescription.contains("<html>"))
        }
        GrandSlamProtocol.responses.verify(attempts: 5, seconds: [1, 2, 4, 8])
    }
    @Test(arguments: [400, 401, 403, 429]) func clientErrorsAreNotRetried(status: Int) async throws {
        GrandSlamProtocol.responses.reset([status])
        let (data, response) = try await send()
        #expect((response as? HTTPURLResponse)?.statusCode == status)
        #expect(data == GrandSlamProtocol.plist) // Retain structured Apple errors for existing parser.
        GrandSlamProtocol.responses.verify(attempts: 1, seconds: [])
    }
    @Test(arguments: [URLError.Code.timedOut, .notConnectedToInternet, .cancelled])
    func transportErrorsAreNotRetried(code: URLError.Code) async throws {
        GrandSlamProtocol.responses.reset([200], failure: URLError(code))
        do {
            _ = try await send()
            Issue.record("Expected transport error")
        } catch {
            #expect((error as NSError).code == code.rawValue)
        }
        GrandSlamProtocol.responses.verify(attempts: 1, seconds: [])
    }
    @Test func cancellationDuringBackoffStopsRetries() async throws {
        GrandSlamProtocol.responses.reset([503, 200])
        do {
            _ = try await GrandSlamTransport.data(for: request(),
                makeSession: { GrandSlamProtocol.responses.session($0) },
                sleep: { _ in throw CancellationError() })
            Issue.record("Expected cancellation")
        } catch {
            #expect(error is CancellationError)
        }
        GrandSlamProtocol.responses.verify(attempts: 1, seconds: [])
    }
}
