import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Transport for the three GrandSlam authentication exchanges, not general portal requests.
enum GrandSlamTransport {
    static func data(
        for request: URLRequest,
        makeSession: @Sendable (URLSessionConfiguration) -> URLSession = { URLSession(configuration: $0) },
        sleep: @Sendable (UInt64) async throws -> Void = { try await Task.sleep(nanoseconds: $0) }
    ) async throws -> (Data, URLResponse) {
        let retryDelays: [UInt64] = [1, 2, 4, 8]
        var attempt = 0

        while true {
            try Task.checkCancellation()
            // Apple's GSA edge can pin a persistent connection to a failing backend.
            // Each attempt needs its own connection pool, including the initial request.
            let configuration = URLSessionConfiguration.ephemeral
            configuration.urlCache = nil
            configuration.httpCookieStorage = nil
            configuration.urlCredentialStorage = nil
            configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
            let session = makeSession(configuration)
            let result: (Data, URLResponse)
            do {
                // Scope invalidation to this attempt, before any backoff or return.
                defer { session.finishTasksAndInvalidate() }
                result = try await session.data(for: request)
            }
            try Task.checkCancellation()

            guard let response = result.1 as? HTTPURLResponse,
                  (500...599).contains(response.statusCode) else {
                // Keep existing plist/JSON and Apple error handling for all other responses.
                return result
            }

            guard attempt < retryDelays.count else {
                // Never pass an exhausted 5xx HTML body to the plist parser. Do not expose
                // response bodies: authentication responses can contain account secrets.
                throw NSError(domain: NSURLErrorDomain, code: NSURLErrorBadServerResponse, userInfo: [
                    NSLocalizedDescriptionKey: "Apple's authentication server returned HTTP \(response.statusCode) after \(attempt + 1) attempts. Please try again later.",
                    "HTTPStatusCode": response.statusCode,
                    "ContentType": response.value(forHTTPHeaderField: "Content-Type") ?? "unknown"
                ])
            }

            // Only received 5xx responses are retried, never transport errors or cancellation.
            try await sleep(retryDelays[attempt] * 1_000_000_000)
            attempt += 1
        }
    }
}
