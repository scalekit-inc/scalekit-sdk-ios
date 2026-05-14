import XCTest
@testable import ScalekitAuth

final class AuthorizationOptionsTests: XCTestCase {

    func testAllNilProducesEmptyParameters() {
        let params = AuthorizationOptions().asAdditionalParameters
        XCTAssertTrue(params.isEmpty)
    }

    func testOrganizationIdMapsToCorrectKey() {
        let params = AuthorizationOptions(organizationId: "org_123").asAdditionalParameters
        XCTAssertEqual(params["organization_id"], "org_123")
        XCTAssertEqual(params.count, 1)
    }

    func testConnectionIdMapsToCorrectKey() {
        let params = AuthorizationOptions(connectionId: "conn_456").asAdditionalParameters
        XCTAssertEqual(params["connection_id"], "conn_456")
        XCTAssertEqual(params.count, 1)
    }

    func testLoginHintMapsToCorrectKey() {
        let params = AuthorizationOptions(loginHint: "user@example.com").asAdditionalParameters
        XCTAssertEqual(params["login_hint"], "user@example.com")
    }

    func testDomainMapsToCorrectKey() {
        let params = AuthorizationOptions(domain: "example.com").asAdditionalParameters
        XCTAssertEqual(params["domain"], "example.com")
    }

    func testProviderMapsToCorrectKey() {
        let params = AuthorizationOptions(provider: "google").asAdditionalParameters
        XCTAssertEqual(params["provider"], "google")
    }

    func testPromptMapsToCorrectKey() {
        let params = AuthorizationOptions(prompt: "login").asAdditionalParameters
        XCTAssertEqual(params["prompt"], "login")
    }

    func testAllFieldsProducesSixKeys() {
        let options = AuthorizationOptions(
            organizationId: "org_1",
            connectionId: "conn_1",
            loginHint: "user@example.com",
            domain: "example.com",
            provider: "google",
            prompt: "consent"
        )
        let params = options.asAdditionalParameters
        XCTAssertEqual(params.count, 6)
        XCTAssertEqual(params["organization_id"], "org_1")
        XCTAssertEqual(params["connection_id"], "conn_1")
        XCTAssertEqual(params["login_hint"], "user@example.com")
        XCTAssertEqual(params["domain"], "example.com")
        XCTAssertEqual(params["provider"], "google")
        XCTAssertEqual(params["prompt"], "consent")
    }

    func testOnlySetFieldsAppearInParameters() {
        let params = AuthorizationOptions(organizationId: "org_1", provider: "github").asAdditionalParameters
        XCTAssertEqual(params.count, 2)
        XCTAssertEqual(params["organization_id"], "org_1")
        XCTAssertEqual(params["provider"], "github")
        XCTAssertNil(params["connection_id"])
        XCTAssertNil(params["login_hint"])
    }
}
