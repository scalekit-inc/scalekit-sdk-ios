import AppAuth
import Foundation

public struct UserInfo {
    public let sub: String
    public let email: String?
    public let name: String?
    public let picture: String?
    public let rawClaims: [String: Any]
}

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
        return expiry <= Date()
    }

    public var userInfo: UserInfo? {
        guard let idToken, let claims = decodeJWTPayload(idToken) else { return nil }
        return UserInfo(
            sub: claims["sub"] as? String ?? "",
            email: claims["email"] as? String,
            name: claims["name"] as? String,
            picture: claims["picture"] as? String,
            rawClaims: claims
        )
    }

    private func decodeJWTPayload(_ token: String) -> [String: Any]? {
        let parts = token.components(separatedBy: ".")
        guard parts.count == 3 else { return nil }
        var base64 = parts[1]
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.count % 4
        if remainder > 0 { base64 += String(repeating: "=", count: 4 - remainder) }
        guard let data = Data(base64Encoded: base64),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        return json
    }
}
