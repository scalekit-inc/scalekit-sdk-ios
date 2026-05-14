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

    /// Generates an EC P-256 key pair.
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

    /// Exports EC public key components (x, y) as base64url from the 65-byte uncompressed point.
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
        // Skip sequence length (may be multi-byte)
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

    /// Signs a JWT payload with the given EC private key (ES256).
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

    /// Builds a JWKS JSON Data for an EC P-256 public key.
    private func makeES256JWKS(publicKey: SecKey, kid: String) throws -> Data {
        let (x, y) = try ecPublicKeyComponents(publicKey)
        let jwks = """
        {"keys":[{"kty":"EC","crv":"P-256","kid":"\(kid)","alg":"ES256","x":"\(x)","y":"\(y)"}]}
        """
        return Data(jwks.utf8)
    }

    /// Creates a URLSession backed by a mock URLProtocol that serves fixed data for a given URL.
    private func mockSession(url: URL, data: Data) -> URLSession {
        MockURLProtocol.stub(url: url, data: data)
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        return URLSession(configuration: config)
    }

    /// A unique JWKS URL per test to avoid JWKS cache collisions between test runs.
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

        // Should not throw
        try await JWTVerifier.verify(token: jwt, jwksURL: jwksURL, urlSession: session)
    }

    func testES256WrongKeyThrowsSignatureInvalid() async throws {
        let kid = "es256-mismatch-\(UUID().uuidString)"
        let jwksURL = freshJWKSURL()
        let (privateKey, _) = try makeECKeyPair()
        let (_, differentPublicKey) = try makeECKeyPair()  // different key in JWKS
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
        // JWKS has "different-kid" but JWT uses "missing-kid"
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
}

// MARK: - MockURLProtocol

private class MockURLProtocol: URLProtocol {
    private static var stubs: [URL: Data] = [:]

    static func stub(url: URL, data: Data) { stubs[url] = data }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let url = request.url, let data = MockURLProtocol.stubs[url] else {
            client?.urlProtocol(self, didFailWithError: URLError(.fileDoesNotExist))
            return
        }
        let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!
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
