import AppAuth
import Foundation
import Security

class KeychainTokenStore {
    private let service: String
    private let account = "scalekit_auth_state"

    init(service: String) {
        self.service = service
    }

    func save(_ credentials: ScalekitCredentials) {
        guard let data = try? NSKeyedArchiver.archivedData(
            withRootObject: credentials.authState,
            requiringSecureCoding: true
        ) else { return }

        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecValueData: data,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }

    func load() -> ScalekitCredentials? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne
        ]
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data,
              let authState = try? NSKeyedUnarchiver.unarchivedObject(
                  ofClass: OIDAuthState.self, from: data
              )
        else { return nil }
        return ScalekitCredentials(authState: authState)
    }

    func clear() {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account
        ]
        SecItemDelete(query as CFDictionary)
    }
}
