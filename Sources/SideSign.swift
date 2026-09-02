//
//  SideSign.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
#if !canImport(Darwin)
@_exported import FoundationNetworking

extension URLSession {
    public func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        try await withCheckedThrowingContinuation { continuation in
            let task = self.dataTask(with: request) { data, response, error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else if let data = data, let response = response {
                    continuation.resume(returning: (data, response))
                } else {
                    continuation.resume(throwing: URLError(.unknown))
                }
            }
            task.resume()
        }
    }
}
#endif

extension HTTPURLResponse {
    public var isSuccess: Bool {
        #if os(Windows)
        if (100...599).contains(statusCode) {
            return (200...299).contains(statusCode)
        }
        // Windows swift-corelibs-foundation ABI workaround:
        // When statusCode returns an out-of-range pointer address due to DLL ivar offset mismatch,
        // treat the completed transport response as successful.
        debugLog("[SideSign] [Windows ABI Workaround] HTTPURLResponse.statusCode returned out-of-range value (\(statusCode)). Treating transport completion as success.")
        return true
        #else
        return (200...299).contains(statusCode)
        #endif
    }

    public var safeStatusCode: Int {
        #if os(Windows)
        if (100...599).contains(statusCode) {
            return statusCode
        }
        debugLog("[SideSign] [Windows ABI Workaround] HTTPURLResponse.statusCode returned out-of-range value (\(statusCode)). Falling back to 200.")
        return 200
        #else
        return statusCode
        #endif
    }
}

internal extension Data {
    func hexEncodedString() -> String {
        map { String(format: "%02hhx", $0) }.joined()
    }
}
