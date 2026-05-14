import Foundation

public enum ScalekitError: Error, LocalizedError {
    /// OIDC discovery failed — check the environmentURL is correct and reachable.
    case discoveryFailed
    /// The authorization flow failed for an unknown reason.
    case authFailed
    /// No active session — call login() first.
    case notAuthenticated
    /// No refresh token is available — re-authentication required.
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
    /// The JWT signature could not be verified against Scalekit's public keys.
    case tokenVerificationFailed(underlying: Error)
    /// The ID token nonce does not match — possible replay attack.
    case invalidIDToken

    public var errorDescription: String? {
        switch self {
        case .discoveryFailed:                  return "Failed to load Scalekit configuration."
        case .authFailed:                       return "Authentication failed."
        case .notAuthenticated:                 return "No active session."
        case .noRefreshToken:                   return "No refresh token available. Please sign in again."
        case .sessionRevoked:                   return "Session was revoked. Please sign in again."
        case .renewFailed(let e):               return "Token renewal failed: \(e.localizedDescription)"
        case .networkFailure(let e):            return "Network error: \(e.localizedDescription)"
        case .cancelled:                        return "Sign-in was cancelled."
        case .loginInProgress:                  return "A sign-in is already in progress."
        case .tokenVerificationFailed(let e):   return "Token verification failed: \(e.localizedDescription)"
        case .invalidIDToken:                   return "ID token nonce is invalid. Please sign in again."
        }
    }
}
