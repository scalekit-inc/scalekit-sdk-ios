import Foundation

/// Options for customizing the authorization request.
/// All fields are optional — set only what you need.
public struct AuthorizationOptions: Sendable {
    /// Route to a specific organization (SSO/connection lookup by org).
    public var organizationId: String?
    /// Route to a specific connection directly.
    public var connectionId: String?
    /// Pre-fill the login identifier (email or username).
    public var loginHint: String?
    /// Route by domain — Scalekit resolves the IdP from the domain.
    public var domain: String?
    /// Route to a specific social/IdP provider (e.g. "google", "github").
    public var provider: String?
    /// Controls re-authentication behavior ("login", "consent", "none").
    public var prompt: String?

    public init(
        organizationId: String? = nil,
        connectionId: String? = nil,
        loginHint: String? = nil,
        domain: String? = nil,
        provider: String? = nil,
        prompt: String? = nil
    ) {
        self.organizationId = organizationId
        self.connectionId = connectionId
        self.loginHint = loginHint
        self.domain = domain
        self.provider = provider
        self.prompt = prompt
    }

    var asAdditionalParameters: [String: String] {
        var params: [String: String] = [:]
        if let organizationId { params["organization_id"] = organizationId }
        if let connectionId   { params["connection_id"]   = connectionId   }
        if let loginHint      { params["login_hint"]      = loginHint      }
        if let domain         { params["domain"]          = domain         }
        if let provider       { params["provider"]        = provider       }
        if let prompt         { params["prompt"]          = prompt         }
        return params
    }
}
