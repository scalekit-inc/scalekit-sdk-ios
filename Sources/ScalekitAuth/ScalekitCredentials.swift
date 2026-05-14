import AppAuth
import Foundation

public class ScalekitCredentials {
    let authState: OIDAuthState

    init(authState: OIDAuthState) {
        self.authState = authState
    }

    public var accessToken: String? {
        authState.lastTokenResponse?.accessToken
    }

    public var idToken: String? {
        authState.lastTokenResponse?.idToken
            ?? authState.lastAuthorizationResponse.idToken
    }

    public var isValid: Bool {
        authState.isAuthorized
    }

    public var refreshToken: String? {
        authState.refreshToken
    }

    public var accessTokenExpiryDate: Date? {
        authState.lastTokenResponse?.accessTokenExpirationDate
    }

    public var accessTokenExpired: Bool {
        guard let expiry = accessTokenExpiryDate else { return true }
        return expiry <= .now
    }

    /// Decoded claims from the ID token. Computed once on first access.
    public private(set) lazy var userInfo: UserInfo? = {
        guard let idToken, let claims = JWT.decode(idToken) else { return nil }
        return UserInfo(
            sub: claims["sub"] as? String ?? "",
            email: claims["email"] as? String,
            name: claims["name"] as? String,
            picture: claims["picture"] as? String,
            rawClaims: claims
        )
    }()
}
