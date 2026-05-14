import AppAuth
import Foundation

public class ScalekitCredentials {
    let authState: OIDAuthState

    init(authState: OIDAuthState) {
        self.authState = authState
        let idToken = authState.lastTokenResponse?.idToken
            ?? authState.lastAuthorizationResponse.idToken
        if let idToken, let claims = JWT.decode(idToken) {
            self.userInfo = UserInfo(
                sub: claims["sub"] as? String ?? "",
                email: claims["email"] as? String,
                name: claims["name"] as? String,
                picture: claims["picture"] as? String,
                rawClaims: claims
            )
        } else {
            self.userInfo = nil
        }
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

    /// Decoded claims from the ID token, available immediately after init.
    public let userInfo: UserInfo?
}
