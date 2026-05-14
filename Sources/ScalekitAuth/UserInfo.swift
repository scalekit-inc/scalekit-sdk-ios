import Foundation

public struct UserInfo: @unchecked Sendable {
    public let sub: String
    public let email: String?
    public let name: String?
    public let picture: String?
    public let rawClaims: [String: Any]
}
