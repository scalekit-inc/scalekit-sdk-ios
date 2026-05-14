import XCTest
import Security
@testable import ScalekitAuth

final class JWTVerifierTests: XCTestCase {

    // MARK: - Helpers

    private func base64url(_ data: Data) -> String {
        data.base64EncodedString()
            .replacing("+", with: "-")
            .replacing("/", with: "_")
            .replacing("=", with: "")
    }

    private func makeTokenParts(alg: String, kid: String, claims: [String: Any] = [:]) -> (header: String, payload: String) {
        let header = ["alg": alg, "kid": kid, "typ": "JWT"]
        let payload: [String: Any] = claims.isEmpty
            ? ["sub": "test-user", "iat": 1_700_000_000, "exp": 9_999_999_999]
            : claims
        let h = base64url(try! JSONSerialization.data(withJSONObject: header))
        let p = base64url(try! JSONSerialization.data(withJSONObject: payload))
        return (h, p)
    }

    // MARK: - EC P-256 helpers

    private func makeECKeyPair() throws -> (private: SecKey, public: SecKey) {
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrKeySizeInBits as String: 256
        ]
        var cfError: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attrs as CFDictionary, &cfError),
              let publicKey = SecKeyCopyPublicKey(privateKey)
        else { throw cfError!.takeRetainedValue() as Error }
        return (privateKey, publicKey)
    }

    private func ecPublicKeyComponents(_ key: SecKey) throws -> (x: String, y: String) {
        var cfError: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(key, &cfError) as Data?,
              data.count == 65, data[0] == 0x04
        else { throw cfError?.takeRetainedValue() as? Error ?? URLError(.unknown) }
        return (base64url(data.subdata(in: 1..<33)), base64url(data.subdata(in: 33..<65)))
    }

    /// Converts DER-encoded ECDSA signature (SEQUENCE { INTEGER r, INTEGER s }) to raw 64-byte r||s.
    private func derToRaw(_ der: Data) throws -> Data {
        var i = der.startIndex
        guard der[i] == 0x30 else { throw URLError(.unknown) }
        i = der.index(after: i)
        if der[i] >= 0x80 { i = der.index(i, offsetBy: Int(der[i] & 0x7F)) }
        i = der.index(after: i)

        func readInt() throws -> Data {
            guard der[i] == 0x02 else { throw URLError(.unknown) }
            i = der.index(after: i)
            let len = Int(der[i]); i = der.index(after: i)
            let value = Data(der[i..<der.index(i, offsetBy: len)]); i = der.index(i, offsetBy: len)
            return value
        }
        let r = try readInt()
        let s = try readInt()

        func normalize(_ d: Data, size: Int) -> Data {
            var bytes = Array(d)
            while bytes.count > size && bytes.first == 0x00 { bytes.removeFirst() }
            while bytes.count < size { bytes.insert(0x00, at: 0) }
            return Data(bytes)
        }
        return normalize(r, size: 32) + normalize(s, size: 32)
    }

    private func makeSignedES256JWT(privateKey: SecKey, kid: String) throws -> String {
        let (h, p) = makeTokenParts(alg: "ES256", kid: kid)
        let signingInput = "\(h).\(p)"
        var cfError: Unmanaged<CFError>?
        guard let derSig = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            Data(signingInput.utf8) as CFData,
            &cfError
        ) as Data?
        else { throw cfError!.takeRetainedValue() as Error }
        let rawSig = try derToRaw(derSig)
        return "\(signingInput).\(base64url(rawSig))"
    }

    private func makeES256JWKS(publicKey: SecKey, kid: String) throws -> Data {
        let (x, y) = try ecPublicKeyComponents(publicKey)
        let jwks = """
        {"keys":[{"kty":"EC","crv":"P-256","kid":"\(kid)","alg":"ES256","x":"\(x)","y":"\(y)"}]}
        """
        return Data(jwks.utf8)
    }

    // MARK: - RSA 2048 helpers

    private func makeRSAKeyPair() throws -> (private: SecKey, public: SecKey) {
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048
        ]
        var cfError: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attrs as CFDictionary, &cfError),
              let publicKey = SecKeyCopyPublicKey(privateKey)
        else { throw cfError!.takeRetainedValue() as Error }
        return (privateKey, publicKey)
    }

    /// Extracts n and e from a PKCS#1 DER RSA public key (65-byte format used by SecKeyCopyExternalRepresentation).
    private func rsaPublicKeyComponents(_ key: SecKey) throws -> (n: String, e: String) {
        var cfError: Unmanaged<CFError>?
        guard let der = SecKeyCopyExternalRepresentation(key, &cfError) as Data?
        else { throw cfError?.takeRetainedValue() as? Error ?? URLError(.unknown) }

        // PKCS#1 DER: SEQUENCE { INTEGER n, INTEGER e }
        // Skip outer SEQUENCE tag+length, then read two INTEGERs.
        var i = der.startIndex
        guard der[i] == 0x30 else { throw URLError(.badServerResponse) }
        i = der.index(after: i)
        // Skip sequence length (may be multi-byte)
        if der[i] >= 0x80 {
            let extra = Int(der[i] & 0x7F)
            i = der.index(i, offsetBy: 1 + extra)
        } else {
            i = der.index(after: i)
        }

        func readDERInt() throws -> Data {
            guard der[i] == 0x02 else { throw URLError(.badServerResponse) }
            i = der.index(after: i)
            var len: Int
            if der[i] >= 0x80 {
                let extra = Int(der[i] & 0x7F)
                i = der.index(after: i)
                len = 0
                for _ in 0..<extra {
                    len = (len << 8) | Int(der[i])
                    i = der.index(after: i)
                }
            } else {
                len = Int(der[i])
                i = der.index(after: i)
            }
            let value = Data(der[i..<der.index(i, offsetBy: len)])
            i = der.index(i, offsetBy: len)
            return value
        }

        let n = try readDERInt()
        let e = try readDERInt()

        // Strip leading zero byte that DER uses to indicate positive integer
        let nStripped = n.first == 0x00 ? n.dropFirst() : n
        return (base64url(Data(nStripped)), base64url(e))
    }

    private func makeSignedRS256JWT(privateKey: SecKey, kid: String) throws -> String {
        let (h, p) = makeTokenParts(alg: "RS256", kid: kid)
        let signingInput = "\(h).\(p)"
        var cfError: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(
            privateKey,
            .rsaSignatureMessagePKCS1v15SHA256,
            Data(signingInput.utf8) as CFData,
            &cfError
        ) as Data?
        else { throw cfError!.takeRetainedValue() as Error }
        return "\(signingInput).\(base64url(sig))"
    }

    private func makeRS256JWKS(publicKey: SecKey, kid: String) throws -> Data {
        let (n, e) = try rsaPublicKeyComponents(publicKey)
        let jwks = """
        {"keys":[{"kty":"RSA","kid":"\(kid)","alg":"RS256","n":"\(n)","e":"\(e)"}]}
        """
        return Data(jwks.utf8)
    }

    // MARK: - Session helpers

    private func mockSession(url: URL, data: Data) -> URLSession {
        MockURLProtocol.stub(url: url, data: data)
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        return URLSession(configuration: config)
    }

    /// Unique JWKS URL per test to avoid JWKS cache collisions between test runs.
    private func freshJWKSURL() -> URL {
        URL(string: "https://test.scalekit.invalid/jwks/\(UUID().uuidString)")!
    }

    // MARK: - Malformed token tests

    func testMalformedTokenTwoPartsThrows() async {
        await XCTAssertThrowsErrorAsync(
            try await JWTVerifier.verify(token: "header.payload", jwksURL: freshJWKSURL())
        ) { error in
            XCTAssertEqual(error as? JWTVerifier.Error, .malformedToken)
        }
    }

    func testMalformedTokenInvalidBase64HeaderThrows() async {
        await XCTAssertThrowsErrorAsync(
            try await JWTVerifier.verify(token: "!!!.payload.sig", jwksURL: freshJWKSURL())
        ) { error in
            XCTAssertEqual(error as? JWTVerifier.Error, .malformedToken)
        }
    }

    func testMalformedTokenNonJSONHeaderThrows() async {
        let notJSON = base64url(Data("not json".utf8))
        await XCTAssertThrowsErrorAsync(
            try await JWTVerifier.verify(token: "\(notJSON).payload.sig", jwksURL: freshJWKSURL())
        ) { error in
            XCTAssertEqual(error as? JWTVerifier.Error, .malformedToken)
        }
    }

    func testUnsupportedAlgorithmHS256Throws() async {
        let (h, p) = makeTokenParts(alg: "HS256", kid: "k1")
        await XCTAssertThrowsErrorAsync(
            try await JWTVerifier.verify(token: "\(h).\(p).fakesig", jwksURL: freshJWKSURL())
        ) { error in
            XCTAssertEqual(error as? JWTVerifier.Error, .unsupportedAlgorithm("HS256"))
        }
    }

    func testUnsupportedAlgorithmRS512Throws() async {
        let (h, p) = makeTokenParts(alg: "RS512", kid: "k1")
        await XCTAssertThrowsErrorAsync(
            try await JWTVerifier.verify(token: "\(h).\(p).fakesig", jwksURL: freshJWKSURL())
        ) { error in
            XCTAssertEqual(error as? JWTVerifier.Error, .unsupportedAlgorithm("RS512"))
        }
    }

    // MARK: - ES256 happy path

    func testES256ValidSignatureVerifies() async throws {
        let kid = "es256-test-\(UUID().uuidString)"
        let jwksURL = freshJWKSURL()
        let (privateKey, publicKey) = try makeECKeyPair()
        let jwt = try makeSignedES256JWT(privateKey: privateKey, kid: kid)
        let jwksData = try makeES256JWKS(publicKey: publicKey, kid: kid)
        let session = mockSession(url: jwksURL, data: jwksData)

        try await JWTVerifier.verify(token: jwt, jwksURL: jwksURL, urlSession: session)
    }

    func testES256WrongKeyThrowsSignatureInvalid() async throws {
        let kid = "es256-mismatch-\(UUID().uuidString)"
        let jwksURL = freshJWKSURL()
        let (privateKey, _) = try makeECKeyPair()
        let (_, differentPublicKey) = try makeECKeyPair()
        let jwt = try makeSignedES256JWT(privateKey: privateKey, kid: kid)
        let jwksData = try makeES256JWKS(publicKey: differentPublicKey, kid: kid)
        let session = mockSession(url: jwksURL, data: jwksData)

        await XCTAssertThrowsErrorAsync(
            try await JWTVerifier.verify(token: jwt, jwksURL: jwksURL, urlSession: session)
        ) { error in
            XCTAssertEqual(error as? JWTVerifier.Error, .signatureInvalid)
        }
    }

    func testKeyNotFoundThrowsWhenKidMissing() async throws {
        let jwksURL = freshJWKSURL()
        let (_, publicKey) = try makeECKeyPair()
        let jwksData = try makeES256JWKS(publicKey: publicKey, kid: "different-kid")
        let (privateKey, _) = try makeECKeyPair()
        let jwt = try makeSignedES256JWT(privateKey: privateKey, kid: "missing-kid")
        let session = mockSession(url: jwksURL, data: jwksData)

        await XCTAssertThrowsErrorAsync(
            try await JWTVerifier.verify(token: jwt, jwksURL: jwksURL, urlSession: session)
        ) { error in
            if case JWTVerifier.Error.keyNotFound = error { return }
            XCTFail("Expected keyNotFound, got \(error)")
        }
    }

    // MARK: - RS256 happy path

    func testRS256ValidSignatureVerifies() async throws {
        let kid = "rs256-test-\(UUID().uuidString)"
        let jwksURL = freshJWKSURL()
        let (privateKey, publicKey) = try makeRSAKeyPair()
        let jwt = try makeSignedRS256JWT(privateKey: privateKey, kid: kid)
        let jwksData = try makeRS256JWKS(publicKey: publicKey, kid: kid)
        let session = mockSession(url: jwksURL, data: jwksData)

        try await JWTVerifier.verify(token: jwt, jwksURL: jwksURL, urlSession: session)
    }

    func testRS256WrongKeyThrowsSignatureInvalid() async throws {
        let kid = "rs256-mismatch-\(UUID().uuidString)"
        let jwksURL = freshJWKSURL()
        let (privateKey, _) = try makeRSAKeyPair()
        let (_, differentPublicKey) = try makeRSAKeyPair()
        let jwt = try makeSignedRS256JWT(privateKey: privateKey, kid: kid)
        let jwksData = try makeRS256JWKS(publicKey: differentPublicKey, kid: kid)
        let session = mockSession(url: jwksURL, data: jwksData)

        await XCTAssertThrowsErrorAsync(
            try await JWTVerifier.verify(token: jwt, jwksURL: jwksURL, urlSession: session)
        ) { error in
            XCTAssertEqual(error as? JWTVerifier.Error, .signatureInvalid)
        }
    }
}

// MARK: - MockURLProtocol

private class MockURLProtocol: URLProtocol {
    private static let queue = DispatchQueue(label: "MockURLProtocol.stubs")
    private static var _stubs: [URL: Data] = [:]

    static func stub(url: URL, data: Data) {
        queue.sync { _stubs[url] = data }
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let data = MockURLProtocol.queue.sync { MockURLProtocol._stubs[request.url!] }
        guard let data else {
            client?.urlProtocol(self, didFailWithError: URLError(.fileDoesNotExist))
            return
        }
        let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

// MARK: - Async XCTest helper

func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    _ message: String = "",
    file: StaticString = #filePath,
    line: UInt = #line,
    _ errorHandler: (Error) -> Void = { _ in }
) async {
    do {
        _ = try await expression()
        XCTFail("Expected error but none was thrown. \(message)", file: file, line: line)
    } catch {
        errorHandler(error)
    }
}
