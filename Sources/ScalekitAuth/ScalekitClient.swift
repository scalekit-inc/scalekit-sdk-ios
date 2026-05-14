import AppAuth
import AuthenticationServices
import Combine
import Foundation
import UIKit

/// Options for customizing the authorization request.
/// All fields are optional — set only what you need.
public struct AuthorizationOptions {
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

public enum ScalekitError: Error, LocalizedError {
    case discoveryFailed
    case authFailed
    case notAuthenticated
    case sessionRevoked
    case cancelled

    public var errorDescription: String? {
        switch self {
        case .discoveryFailed:  return "Failed to load Scalekit configuration."
        case .authFailed:       return "Authentication failed."
        case .notAuthenticated: return "No active session."
        case .sessionRevoked:   return "Session was revoked. Please sign in again."
        case .cancelled:        return "Sign-in was cancelled."
        }
    }
}

@MainActor
public class ScalekitClient: NSObject, ObservableObject {
    public let domain: String
    public let clientId: String

    private let redirectURI: URL
    private let tokenStore: KeychainTokenStore
    private var currentAuthFlow: OIDExternalUserAgentSession?

    @Published public var credentials: ScalekitCredentials?

    public var isAuthenticated: Bool { credentials != nil }

    public init(domain: String, clientId: String, redirectScheme: String) {
        self.domain = domain
        self.clientId = clientId
        self.redirectURI = URL(string: "\(redirectScheme):/oauth2redirect")!
        self.tokenStore = KeychainTokenStore(service: "com.scalekit.\(domain)")
        let loaded = tokenStore.load()
        self.credentials = loaded
        super.init()
        loaded?.authState.stateChangeDelegate = self
        loaded?.authState.errorDelegate = self
    }

    // MARK: - Login

    public func login(options: AuthorizationOptions = .init()) async throws {
        let config = try await discoverConfig()
        let extra = options.asAdditionalParameters

        let request = OIDAuthorizationRequest(
            configuration: config,
            clientId: clientId,
            scopes: [OIDScopeOpenID, OIDScopeProfile, OIDScopeEmail, "offline_access"],
            redirectURL: redirectURI,
            responseType: OIDResponseTypeCode,
            additionalParameters: extra.isEmpty ? nil : extra
        )

        let vc = try topViewController()
        let authState: OIDAuthState = try await withCheckedThrowingContinuation { continuation in
            let flow = OIDAuthState.authState(byPresenting: request, presenting: vc) { [weak self] state, error in
                self?.currentAuthFlow = nil
                if let state {
                    continuation.resume(returning: state)
                } else if let error = error as NSError?, error.code == OIDErrorCode.userCanceledAuthorizationFlow.rawValue {
                    continuation.resume(throwing: ScalekitError.cancelled)
                } else {
                    continuation.resume(throwing: error ?? ScalekitError.authFailed)
                }
            }
            self.currentAuthFlow = flow
        }

        let creds = ScalekitCredentials(authState: authState)
        authState.stateChangeDelegate = self
        authState.errorDelegate = self
        tokenStore.save(creds)
        credentials = creds
    }

    // MARK: - Logout

    public func logout() async {
        defer {
            tokenStore.clear()
            credentials = nil
        }
        await fireEndSession()
    }

    // MARK: - Renew

    /// Refreshes the access token if expired. Call before any API request.
    public func renew() async throws {
        guard let creds = credentials else { throw ScalekitError.notAuthenticated }

        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            creds.authState.performAction { [weak self] _, _, error in
                if let error {
                    let nsError = error as NSError
                    if nsError.domain == OIDOAuthTokenErrorDomain {
                        cont.resume(throwing: ScalekitError.sessionRevoked)
                    } else {
                        cont.resume(throwing: error)
                    }
                } else {
                    self?.tokenStore.save(creds)
                    cont.resume()
                }
            }
        }
    }

    // MARK: - Private

    private func discoverConfig() async throws -> OIDServiceConfiguration {
        let issuer = URL(string: "https://\(domain)")!
        return try await withCheckedThrowingContinuation { continuation in
            OIDAuthorizationService.discoverConfiguration(forIssuer: issuer) { config, error in
                if let config {
                    continuation.resume(returning: config)
                } else {
                    continuation.resume(throwing: error ?? ScalekitError.discoveryFailed)
                }
            }
        }
    }

    private func fireEndSession() async {
        guard let idToken = credentials?.idToken else { return }

        let endpoint = credentials?.authState
            .lastAuthorizationResponse.request.configuration
            .discoveryDocument?.endSessionEndpoint
            ?? URL(string: "https://\(domain)/oidc/logout")!

        var components = URLComponents(url: endpoint, resolvingAgainstBaseURL: true)!
        components.queryItems = [
            URLQueryItem(name: "id_token_hint", value: idToken),
            URLQueryItem(name: "post_logout_redirect_uri", value: "\(redirectURI.scheme!)://logout")
        ]
        guard let url = components.url else { return }

        _ = try? await withCheckedThrowingContinuation { (cont: CheckedContinuation<URL?, Error>) in
            let session = ASWebAuthenticationSession(
                url: url,
                callbackURLScheme: redirectURI.scheme
            ) { callbackURL, error in
                cont.resume(returning: callbackURL)
            }
            session.prefersEphemeralWebBrowserSession = false
            session.presentationContextProvider = self.presentationContext
            session.start()
            self.logoutSession = session
        }
        logoutSession = nil
    }

    private var logoutSession: ASWebAuthenticationSession?
    private let presentationContext = PresentationContext()

    private func topViewController() throws -> UIViewController {
        guard let scene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
              let root = scene.windows.first(where: \.isKeyWindow)?.rootViewController
        else { throw ScalekitError.authFailed }
        var top = root
        while let presented = top.presentedViewController { top = presented }
        return top
    }
}

extension ScalekitClient: OIDAuthStateChangeDelegate {
    public nonisolated func didChange(_ state: OIDAuthState) {
        // Called by AppAuth on every token update, including refresh token rotation.
        // Save immediately so the rotated refresh token is never lost.
        let creds = ScalekitCredentials(authState: state)
        Task { @MainActor in
            print("[ScalekitAuth] Token state changed — saving rotated tokens to Keychain")
            self.tokenStore.save(creds)
        }
    }
}

extension ScalekitClient: OIDAuthStateErrorDelegate {
    public nonisolated func authState(_ state: OIDAuthState, didEncounterAuthorizationError error: Error) {
        print("[ScalekitAuth] Authorization error: \(error.localizedDescription)")
        Task { @MainActor in
            await self.logout()
        }
    }
}

private class PresentationContext: NSObject, ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap { $0.windows }
            .first(where: \.isKeyWindow) ?? ASPresentationAnchor()
    }
}
