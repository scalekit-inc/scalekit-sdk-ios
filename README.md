# Scalekit iOS SDK

Native iOS authentication for Scalekit — login, session management, and logout via AppAuth.

## Requirements

- iOS 15+
- Swift 5.9+
- Xcode 15+

## Installation

### Swift Package Manager

In Xcode: File → Add Package Dependencies

```
https://github.com/scalekit-inc/scalekit-sdk-ios
```

Or in `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/scalekit-inc/scalekit-sdk-ios", from: "0.2.1")
]
```

## Setup

### 1. Register a redirect URI

In the Scalekit dashboard, register a redirect URI for your app:

```
com.your.bundleid:/oauth2redirect
```

### 2. Add the URL scheme to Info.plist

```xml
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleURLSchemes</key>
    <array>
      <string>com.your.bundleid</string>
    </array>
  </dict>
</array>
```

### 3. Initialize the client

```swift
import ScalekitAuth

@main
struct MyApp: App {
    @StateObject private var client = ScalekitClient(
        environmentURL: "your-env.scalekit.cloud",
        clientId: "your_client_id",
        redirectScheme: "com.your.bundleid"
    )

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(client)
        }
    }
}
```

## Usage

### Login

```swift
// Basic login
try await client.login()

// With organization routing (SSO)
try await client.login(options: .init(organizationId: "org_123456"))
```

### Access user info

```swift
if let user = client.credentials?.userInfo {
    print(user.name)   // "Jane Doe"
    print(user.email)  // "jane@acme.com"
    print(user.sub)    // "usr_123456"
}
```

### Access token claims

If your backend embeds custom claims in the access token, use `decodedClaims(from:)` to verify the JWT signature and extract them:

```swift
do {
    let claims = try await client.decodedClaims(from: accessToken)
    let role = claims["role"] as? String
} catch {
    // ScalekitError.tokenVerificationFailed if signature is invalid
}
```

This works for both access tokens and ID tokens. The signature is verified against Scalekit's JWKS before the claims are returned.

### Refresh tokens

```swift
// Call before any protected API request.
// No-op if the access token is still valid.
try await client.renew()

let accessToken = client.credentials?.accessToken
```

### Logout

```swift
await client.logout()
```

Register the post-logout redirect URI in the Scalekit dashboard:

```
com.your.bundleid://logout
```

## Session management

The SDK handles the full session lifecycle automatically:

- Tokens are persisted in the iOS Keychain
- Access tokens are refreshed silently when expired
- Rotated refresh tokens are saved immediately via `OIDAuthStateChangeDelegate`
- Server-side session revocation surfaces as `ScalekitError.sessionRevoked`

To refresh on app foreground, add to your root view:

```swift
.task { await refreshOrLogout() }
.onReceive(NotificationCenter.default.publisher(
    for: UIApplication.willEnterForegroundNotification)
) { _ in
    Task { await refreshOrLogout() }
}

private func refreshOrLogout() async {
    guard client.isAuthenticated else { return }
    do {
        try await client.renew()
    } catch ScalekitError.sessionRevoked {
        await client.logout()
    } catch { }
}
```

## Sample app

See [scalekit-samples-ios](https://github.com/scalekit-inc/scalekit-samples-ios) for a full working example.

## License

MIT
