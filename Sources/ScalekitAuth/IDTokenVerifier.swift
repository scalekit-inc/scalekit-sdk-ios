import CryptoKit
import Foundation
import Security

// Verifies the RS256 or ES256 signature of an OIDC ID token against
// the server's JWKS. Cryptographic proof the token came from Scalekit
// and was not tampered with in transit.
enum IDTokenVerifier {

    enum Error: Swift.Error, LocalizedError {
        case malformedToken
        case unsupportedAlgorithm(String)
        case keyNotFound(kid: String)
        case invalidKey
        case signatureInvalid

        var errorDescription: String? {
            switch self {
            case .malformedToken:              return "ID token is malformed."
            case .unsupportedAlgorithm(let a): return "Unsupported JWT algorithm: \(a)."
            case .keyNotFound(let k):          return "No JWKS key found for kid=\(k)."
            case .invalidKey:                  return "Could not construct verification key from JWKS."
            case .signatureInvalid:            return "ID token signature is invalid."
            }
        }
    }

    // MARK: - Cache (actor-isolated for thread safety)

    private struct CacheEntry {
        let keys: [[String: Any]]
        let fetchedAt: Date
        var isExpired: Bool { Date.now.timeIntervalSince(fetchedAt) > 86_400 } // 24 h
    }

    private actor JWKSCache {
        var store: [URL: CacheEntry] = [:]

        func entry(for url: URL) -> CacheEntry? { store[url] }
        func set(_ entry: CacheEntry, for url: URL) { store[url] = entry }
    }

    private static let jwksCache = JWKSCache()

    // MARK: - Public

    static func verify(idToken: String, jwksURL: URL) async throws {
        let parts = idToken.components(separatedBy: ".")
        guard parts.count == 3 else { throw Error.malformedToken }

        guard let headerData = base64urlDecode(parts[0]),
              let header = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any]
        else { throw Error.malformedToken }

        guard let alg = header["alg"] as? String else { throw Error.malformedToken }
        guard alg == "RS256" || alg == "ES256" else { throw Error.unsupportedAlgorithm(alg) }

        let kid = header["kid"] as? String ?? ""
        let signingInput = Data((parts[0] + "." + parts[1]).utf8)
        guard let rawSig = base64urlDecode(parts[2]) else { throw Error.malformedToken }

        // Try cached keys first; re-fetch if expired or kid not found
        let jwk = try await resolveKey(kid: kid, alg: alg, jwksURL: jwksURL, allowRefetch: true)
        try verifySignature(alg: alg, signingInput: signingInput, rawSig: rawSig, jwk: jwk)
    }

    // MARK: - Cache resolution

    private static func resolveKey(
        kid: String, alg: String, jwksURL: URL, allowRefetch: Bool
    ) async throws -> [String: Any] {
        // Use cache if present and fresh
        if let entry = await jwksCache.entry(for: jwksURL), !entry.isExpired {
            if let jwk = findKey(kid: kid, alg: alg, in: entry.keys) { return jwk }
            // kid not in cache — fall through to refetch if allowed
            guard allowRefetch else { throw Error.keyNotFound(kid: kid) }
        }

        // Fetch and cache
        let keys = try await fetchKeys(from: jwksURL)
        await jwksCache.set(CacheEntry(keys: keys, fetchedAt: .now), for: jwksURL)

        guard let jwk = findKey(kid: kid, alg: alg, in: keys) else {
            throw Error.keyNotFound(kid: kid)
        }
        return jwk
    }

    private static func findKey(kid: String, alg: String, in keys: [[String: Any]]) -> [String: Any]? {
        keys.first(where: { ($0["kid"] as? String) == kid && !kid.isEmpty })
            ?? keys.first(where: { ($0["alg"] as? String) == alg })
    }

    private static func fetchKeys(from url: URL) async throws -> [[String: Any]] {
        let (data, _) = try await URLSession.shared.data(from: url)
        guard let jwks = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let keys = jwks["keys"] as? [[String: Any]]
        else { throw Error.malformedToken }
        return keys
    }

    // MARK: - Signature verification

    private static func verifySignature(
        alg: String, signingInput: Data, rawSig: Data, jwk: [String: Any]
    ) throws {
        let key = try buildKey(from: jwk, alg: alg)
        var cfError: Unmanaged<CFError>?

        if alg == "RS256" {
            guard SecKeyVerifySignature(key, .rsaSignatureMessagePKCS1v15SHA256,
                                        signingInput as CFData, rawSig as CFData, &cfError)
            else { throw Error.signatureInvalid }
        } else {
            // ES256: JWT raw signature is r||s; Security.framework wants DER-encoded ECDSA
            let derSig = derEncodeECDSA(rawSig)
            guard SecKeyVerifySignature(key, .ecdsaSignatureMessageX962SHA256,
                                        signingInput as CFData, derSig as CFData, &cfError)
            else { throw Error.signatureInvalid }
        }
    }

    // MARK: - Key construction

    private static func buildKey(from jwk: [String: Any], alg: String) throws -> SecKey {
        alg == "RS256" ? try buildRSAKey(jwk) : try buildECKey(jwk)
    }

    private static func buildRSAKey(_ jwk: [String: Any]) throws -> SecKey {
        guard let n = base64urlDecode(jwk["n"] as? String ?? ""),
              let e = base64urlDecode(jwk["e"] as? String ?? "")
        else { throw Error.invalidKey }
        let keyData = pkcs1DER(modulus: n, exponent: e)
        let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                                    kSecAttrKeyClass as String: kSecAttrKeyClassPublic]
        var err: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(keyData as CFData, attrs as CFDictionary, &err)
        else { throw Error.invalidKey }
        return key
    }

    private static func buildECKey(_ jwk: [String: Any]) throws -> SecKey {
        guard let x = base64urlDecode(jwk["x"] as? String ?? ""),
              let y = base64urlDecode(jwk["y"] as? String ?? "")
        else { throw Error.invalidKey }
        var keyData = Data([0x04]) // uncompressed EC point prefix
        keyData += x
        keyData += y
        let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeEC,
                                    kSecAttrKeyClass as String: kSecAttrKeyClassPublic]
        var err: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(keyData as CFData, attrs as CFDictionary, &err)
        else { throw Error.invalidKey }
        return key
    }

    // MARK: - DER encoding

    /// Builds PKCS#1 DER RSA public key: SEQUENCE { INTEGER n, INTEGER e }
    private static func pkcs1DER(modulus: Data, exponent: Data) -> Data {
        asnSeq(asnInt(modulus) + asnInt(exponent))
    }

    /// Converts JWT raw ECDSA signature (r || s) to DER: SEQUENCE { INTEGER r, INTEGER s }
    private static func derEncodeECDSA(_ raw: Data) -> Data {
        let half = raw.count / 2
        return asnSeq(asnInt(Data(raw.prefix(half))) + asnInt(Data(raw.suffix(half))))
    }

    private static func asnInt(_ bytes: Data) -> Data {
        var b = bytes
        while b.count > 1 && b.first == 0x00 { b = b.dropFirst() }
        if b.first ?? 0 >= 0x80 { b = Data([0x00]) + b }
        return Data([0x02]) + asnLen(b.count) + b
    }

    private static func asnSeq(_ content: Data) -> Data {
        Data([0x30]) + asnLen(content.count) + content
    }

    private static func asnLen(_ n: Int) -> Data {
        if n < 128  { return Data([UInt8(n)]) }
        if n < 256  { return Data([0x81, UInt8(n)]) }
        return Data([0x82, UInt8(n >> 8), UInt8(n & 0xFF)])
    }

    private static func base64urlDecode(_ string: String) -> Data? {
        var s = string.replacing("-", with: "+").replacing("_", with: "/")
        let rem = s.count % 4
        if rem > 0 { s += String(repeating: "=", count: 4 - rem) }
        return Data(base64Encoded: s)
    }
}
