import Foundation

/// Accepts "https://env.scalekit.cloud", "env.scalekit.cloud", or
/// "https://env.scalekit.cloud/" and returns the bare host in all cases.
func extractHost(_ raw: String) -> String {
    let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
    if trimmed.contains("://"),
       let url = URL(string: trimmed),
       let host = url.host {
        return host
    }
    return trimmed.components(separatedBy: "/").first ?? trimmed
}
