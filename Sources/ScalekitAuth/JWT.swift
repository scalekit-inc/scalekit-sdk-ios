import Foundation

enum JWT {
    static func claim(_ key: String, from token: String) -> String? {
        decode(token)?[key] as? String
    }

    static func decode(_ token: String) -> [String: Any]? {
        let parts = token.components(separatedBy: ".")
        guard parts.count == 3 else { return nil }
        var base64 = parts[1]
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let rem = base64.count % 4
        if rem > 0 { base64 += String(repeating: "=", count: 4 - rem) }
        guard let data = Data(base64Encoded: base64),
              let claims = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        return claims
    }
}
