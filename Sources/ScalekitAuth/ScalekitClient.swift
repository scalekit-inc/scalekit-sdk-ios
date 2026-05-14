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

// MARK: - Errors

public enum ScalekitError: Error, LocalizedError {
    /// OIDC discovery failed — check the environmentURL is correct and reachable.
    case discoveryFailed
    /// The authorization flow failed for an unknown reason.
    case authFailed
    /// No active session — call login() first.
    case notAuthenticated
    /// The refresh token has no refresh token stored — re-login required.
    case noRefreshToken
    /// The server rejected the refresh token — session was revoked.
    case sessionRevoked
    /// Token renewal failed due to a server or network error.
    case renewFailed(underlying: Error)
    /// A network error occurred.
    case networkFailure(underlying: Error)
    /// The user cancelled the sign-in flow.
    case cancelled
    /// A login is already in progress — wait for it to complete.
    case loginInProgress
    /// The ID token returned by the server is missing or has an invalid nonce.
    case invalidIDToken

    public var errorDescription: String? {
        switch self {
        case .discoveryFailed:           return "Failed to load Scalekit configuration."
        case .authFailed:                return "Authentication failed."
        case .notAuthenticated:          return "No active session."
        case .noRefreshToken:            return "No refresh token available. Please sign in again."
        case .sessionRevoked:            return "Session was revoked. Please sign in again."
        case .renewFailed(let e):        return "Token renewal failed: \(e.localizedDescription)"
        case .networkFailure(let e):     return "Network error: \(e.localizedDescription)"
        case .cancelled:                 return "Sign-in was cancelled."
        case .loginInProgress:           return "A sign-in is already in progress."
        case .invalidIDToken:            return "The ID token is invalid. Please sign in again."
        }
    }
}

// MARK: - Client

@MainActor
public class ScalekitClient: NSObject, ObservableObject {
    /// The normalized environment host (scheme and trailing slashes stripped).
    public let environmentURL: String
    public let clientId: String

    private let redirectURI: URL
    private let tokenStore: KeychainTokenStore

    /// In-flight login flow — prevents concurrent login attempts.
    private var currentAuthFlow: OIDExternalUserAgentSession?
    private var isLoginInProgress = false

    /// In-flight refresh task — concurrent renew() calls share this task
    /// instead of each triggering a separate token exchange.
    /// Critical for Scalekit's rotating refresh tokens: a second concurrent
    /// exchange would fail because the first already consumed the token.
    private var refreshTask: Task<Void, Error>?

    @Published public var credentials: ScalekitCredentials?

    public var isAuthenticated: Bool { credentials != nil }

    public init(environmentURL: String, clientId: String, redirectScheme: String) {
        self.environmentURL = Self.extractHost(environmentURL)
        self.clientId = clientId
        self.redirectURI = URL(string: "\(redirectScheme):/oauth2redirect")!
        self.tokenStore = KeychainTokenStore(service: "com.scalekit.\(self.environmentURL)")
        let loaded = tokenStore.load()
        self.credentials = loaded
        super.init()
        loaded?.authState.stateChangeDelegate = self
        loaded?.authState.errorDelegate = self
    }

    /// Accepts "https://env.scalekit.cloud", "env.scalekit.cloud", or
    /// "https://env.scalekit.cloud/" and returns the bare host in all cases.
    private static func extractHost(_ raw: String) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.contains("://"),
           let url = URL(string: trimmed),
           let host = url.host {
            return host
        }
        return trimmed.components(separatedBy: "/").first ?? trimmed
    }

    // MARK: - Login

    public func login(options: AuthorizationOptions = .init()) async throws {
        guard !isLoginInProgress else { throw ScalekitError.loginInProgress }
        isLoginInProgress = true
        defer { isLoginInProgress = false }

        let config = try await discoverConfig()
        var extra = options.asAdditionalParameters
        let nonce = Self.generateNonce()
        extra["nonce"] = nonce

        let request = OIDAuthorizationRequest(
            configuration: config,
            clientId: clientId,
            scopes: [OIDScopeOpenID, OIDScopeProfile, OIDScopeEmail, "offline_access"],
            redirectURL: redirectURI,
            responseType: OIDResponseTypeCode,
            additionalParameters: extra
        )

        let vc = try topViewController()
        let authState: OIDAuthState = try await withCheckedThrowingContinuation { continuation in
            let flow = OIDAuthState.authState(byPresenting: request, presenting: vc) { [weak self] state, error in
                self?.currentAuthFlow = nil
                if let state {
                    continuation.resume(returning: state)
                } else if let error = error as NSError?,
                          error.code == OIDErrorCode.userCanceledAuthorizationFlow.rawValue {
                    continuation.resume(throwing: ScalekitError.cancelled)
                } else {
                    continuation.resume(throwing: error ?? ScalekitError.authFailed)
                }
            }
            self.currentAuthFlow = flow
        }

        try Self.validateNonce(nonce, in: authState)
        let creds = ScalekitCredentials(authState: authState)
        authState.stateChangeDelegate = self
        authState.errorDelegate = self
        tokenStore.save(creds)
        credentials = creds
    }

    // MARK: - Logout

    public func logout() async {
        refreshTask?.cancel()
        refreshTask = nil
        defer {
            tokenStore.clear()
            credentials = nil
        }
        await fireEndSession()
    }

    // MARK: - Renew

    /// Refreshes the access token if expired.
    /// Concurrent calls are coalesced — all callers await the same in-flight
    /// refresh instead of each triggering a separate token exchange.
    public func renew() async throws {
        if let existing = refreshTask {
            return try await existing.value
        }

        let task = Task<Void, Error> {
            guard let creds = self.credentials else {
                throw ScalekitError.notAuthenticated
            }
            guard creds.authState.refreshToken != nil else {
                throw ScalekitError.noRefreshToken
            }

            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                creds.authState.performAction { [weak self] _, _, error in
                    if let error {
                        let nsError = error as NSError
                        if nsError.domain == OIDOAuthTokenErrorDomain {
                            cont.resume(throwing: ScalekitError.sessionRevoked)
                        } else if (nsError as URLError?)?.code == .notConnectedToInternet
                               || nsError.domain == NSURLErrorDomain {
                            cont.resume(throwing: ScalekitError.networkFailure(underlying: error))
                        } else {
                            cont.resume(throwing: ScalekitError.renewFailed(underlying: error))
                        }
                    } else {
                        self?.tokenStore.save(creds)
                        cont.resume()
                    }
                }
            }
        }

        refreshTask = task
        defer { refreshTask = nil }
        try await task.value
    }

    // MARK: - Private

    /// Generates a cryptographically random 32-byte nonce, base64url-encoded.
    private static func generateNonce() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Decodes the ID token and verifies its nonce claim matches what was sent.
    private static func validateNonce(_ nonce: String, in authState: OIDAuthState) throws {
        let idToken = authState.lastTokenResponse?.idToken
            ?? authState.lastAuthorizationResponse.idToken
        guard let idToken else { throw ScalekitError.invalidIDToken }
        let parts = idToken.components(separatedBy: ".")
        guard parts.count == 3 else { throw ScalekitError.invalidIDToken }
        var base64 = parts[1]
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let rem = base64.count % 4
        if rem > 0 { base64 += String(repeating: "=", count: 4 - rem) }
        guard let data = Data(base64Encoded: base64),
              let claims = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let tokenNonce = claims["nonce"] as? String,
              tokenNonce == nonce
        else { throw ScalekitError.invalidIDToken }
    }

    private func discoverConfig() async throws -> OIDServiceConfiguration {
        let issuer = URL(string: "https://\(environmentURL)")!
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
            ?? URL(string: "https://\(environmentURL)/oidc/logout")!

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

// MARK: - AppAuth Delegates

extension ScalekitClient: OIDAuthStateChangeDelegate {
    public nonisolated func didChange(_ state: OIDAuthState) {
        let creds = ScalekitCredentials(authState: state)
        Task { @MainActor in
            self.tokenStore.save(creds)
        }
    }
}

extension ScalekitClient: OIDAuthStateErrorDelegate {
    public nonisolated func authState(_ state: OIDAuthState, didEncounterAuthorizationError error: Error) {
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
