import XCTest
@testable import ScalekitAuth

final class ScalekitErrorTests: XCTestCase {

    // MARK: - Error descriptions

    func testDiscoveryFailedDescription() {
        XCTAssertEqual(ScalekitError.discoveryFailed.errorDescription,
                       "Failed to load Scalekit configuration.")
    }

    func testAuthFailedDescription() {
        XCTAssertEqual(ScalekitError.authFailed.errorDescription, "Authentication failed.")
    }

    func testNotAuthenticatedDescription() {
        XCTAssertEqual(ScalekitError.notAuthenticated.errorDescription, "No active session.")
    }

    func testNoRefreshTokenDescription() {
        XCTAssertEqual(ScalekitError.noRefreshToken.errorDescription,
                       "No refresh token available. Please sign in again.")
    }

    func testSessionRevokedDescription() {
        XCTAssertEqual(ScalekitError.sessionRevoked.errorDescription,
                       "Session was revoked. Please sign in again.")
    }

    func testCancelledDescription() {
        XCTAssertEqual(ScalekitError.cancelled.errorDescription, "Sign-in was cancelled.")
    }

    func testLoginInProgressDescription() {
        XCTAssertEqual(ScalekitError.loginInProgress.errorDescription,
                       "A sign-in is already in progress.")
    }

    func testInvalidIDTokenDescription() {
        XCTAssertEqual(ScalekitError.invalidIDToken.errorDescription,
                       "ID token nonce is invalid. Please sign in again.")
    }

    // MARK: - Errors that wrap an underlying error

    func testRenewFailedPropagatesUnderlyingMessage() {
        let underlying = URLError(.timedOut)
        let description = ScalekitError.renewFailed(underlying: underlying).errorDescription ?? ""
        XCTAssertTrue(description.hasPrefix("Token renewal failed:"))
        XCTAssertTrue(description.contains(underlying.localizedDescription))
    }

    func testNetworkFailurePropagatesUnderlyingMessage() {
        let underlying = URLError(.notConnectedToInternet)
        let description = ScalekitError.networkFailure(underlying: underlying).errorDescription ?? ""
        XCTAssertTrue(description.hasPrefix("Network error:"))
        XCTAssertTrue(description.contains(underlying.localizedDescription))
    }

    func testTokenVerificationFailedPropagatesUnderlyingMessage() {
        let underlying = URLError(.cannotConnectToHost)
        let description = ScalekitError.tokenVerificationFailed(underlying: underlying).errorDescription ?? ""
        XCTAssertTrue(description.hasPrefix("Token verification failed:"))
        XCTAssertTrue(description.contains(underlying.localizedDescription))
    }

    // MARK: - extractHost

    func testExtractHostStripsScheme() {
        XCTAssertEqual(extractHost("https://env.scalekit.cloud"), "env.scalekit.cloud")
    }

    func testExtractHostStripsTrailingSlash() {
        XCTAssertEqual(extractHost("https://env.scalekit.cloud/"), "env.scalekit.cloud")
    }

    func testExtractHostPassesThroughBareHost() {
        XCTAssertEqual(extractHost("env.scalekit.cloud"), "env.scalekit.cloud")
    }

    func testExtractHostStripsPathFromBareHost() {
        XCTAssertEqual(extractHost("env.scalekit.cloud/some/path"), "env.scalekit.cloud")
    }

    func testExtractHostTrimsWhitespace() {
        XCTAssertEqual(extractHost("  https://env.scalekit.cloud  "), "env.scalekit.cloud")
    }
}
