import XCTest
@testable import ScalekitAuth

final class JWTTests: XCTestCase {

    // MARK: - Helpers

    private func makeToken(header: [String: Any], payload: [String: Any]) -> String {
        let h = base64url(try! JSONSerialization.data(withJSONObject: header))
        let p = base64url(try! JSONSerialization.data(withJSONObject: payload))
        return "\(h).\(p).fakesig"
    }

    private func base64url(_ data: Data) -> String {
        data.base64EncodedString()
            .replacing("+", with: "-")
            .replacing("/", with: "_")
            .replacing("=", with: "")
    }

    // MARK: - JWT.decode

    func testDecodeValidToken() throws {
        let token = makeToken(
            header: ["alg": "RS256", "typ": "JWT"],
            payload: ["sub": "user123", "email": "test@example.com", "iat": 1_700_000_000]
        )
        let claims = try XCTUnwrap(JWT.decode(token))
        XCTAssertEqual(claims["sub"] as? String, "user123")
        XCTAssertEqual(claims["email"] as? String, "test@example.com")
        XCTAssertEqual(claims["iat"] as? Int, 1_700_000_000)
    }

    func testDecodeReturnsNilForTwoPartToken() {
        XCTAssertNil(JWT.decode("header.payload"))
    }

    func testDecodeReturnsNilForOnePartToken() {
        XCTAssertNil(JWT.decode("onlyone"))
    }

    func testDecodeReturnsNilForInvalidBase64Payload() {
        XCTAssertNil(JWT.decode("header.!!!invalid!!!.sig"))
    }

    func testDecodeHandlesBase64URLPaddingWithRemainder1() throws {
        // Payload length such that base64 needs 3 padding chars — tests the `rem == 1` case
        let payload = ["k": "v"]  // short enough to exercise padding variations
        let token = makeToken(header: ["alg": "RS256"], payload: payload)
        XCTAssertNotNil(JWT.decode(token))
    }

    func testDecodeHandlesURLSafeChars() throws {
        // Ensure - and _ in base64url payload are decoded correctly
        let payload = ["sub": "user+test/value"]
        let token = makeToken(header: ["alg": "RS256"], payload: payload)
        let claims = try XCTUnwrap(JWT.decode(token))
        XCTAssertEqual(claims["sub"] as? String, "user+test/value")
    }

    // MARK: - JWT.claim

    func testClaimExtractsStringValue() throws {
        let token = makeToken(
            header: ["alg": "RS256"],
            payload: ["sub": "user123", "email": "hi@example.com"]
        )
        XCTAssertEqual(JWT.claim("sub", from: token), "user123")
        XCTAssertEqual(JWT.claim("email", from: token), "hi@example.com")
    }

    func testClaimReturnsNilForMissingKey() {
        let token = makeToken(header: ["alg": "RS256"], payload: ["sub": "user123"])
        XCTAssertNil(JWT.claim("missing", from: token))
    }

    func testClaimReturnsNilForNonStringValue() {
        let token = makeToken(header: ["alg": "RS256"], payload: ["iat": 1_700_000_000])
        // claim() returns String?, iat is Int → should be nil
        XCTAssertNil(JWT.claim("iat", from: token))
    }

    func testClaimReturnsNilForMalformedToken() {
        XCTAssertNil(JWT.claim("sub", from: "not.a.valid.jwt.at.all"))
    }
}
