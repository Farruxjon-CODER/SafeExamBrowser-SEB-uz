// ============================================================================
// SafeExamBrowser - Stage 1: Configuration
// Central configuration for the Safe Exam Browser kiosk application.
// All security-related settings are consolidated here for easy auditing.
// ============================================================================

namespace SafeExamBrowser.Config
{
    /// <summary>
    /// Centralized application configuration.
    /// Modify these values to customize the exam environment.
    /// </summary>
    public static class AppConfig
    {
        // ── Exam URL ────────────────────────────────────────────────────
        /// <summary>
        /// The primary URL loaded when the kiosk starts.
        /// Change this to your exam platform's URL.
        /// </summary>
        public const string ExamUrl = "https://www.savol-xona.uz";

        // ── URL Whitelist ───────────────────────────────────────────────
        /// <summary>
        /// Only domains in this list (and their subdomains) are allowed.
        /// Navigation to any other domain is silently blocked.
        /// </summary>
        public static readonly string[] AllowedDomains = new[]
        {
            "savol-xona.uz",
            "www.savol-xona.uz"
            // Add your exam platform domains here:
            // "exam.university.edu",
            // "cdn.university.edu",
        };

        // ── Blocked URI Schemes ─────────────────────────────────────────
        /// <summary>
        /// URI schemes that are always blocked regardless of domain.
        /// Prevents access to local files, browser internals, and JS injection.
        /// </summary>
        public static readonly string[] BlockedSchemes = new[]
        {
            "file",
            "chrome",
            "edge",
            "about",
            "javascript",
            "data",    // Blocks data: URIs used for XSS
            "blob",    // Blocks blob: URIs
            "ftp",     // No FTP access
        };

        // ── Admin Exit Password ──────────────────────────────────────────
        /// <summary>
        /// Password required to exit the kiosk via Ctrl+Shift+Q.
        /// In production, use a strong password or integrate with
        /// a server-side authentication API.
        /// </summary>
        public const string AdminPassword = "admin123";

        // ── Window Title ────────────────────────────────────────────────
        public const string WindowTitle = "Xavfsiz imtihon brauzeri";

        // ── WebView2 User Data Folder ───────────────────────────────────
        /// <summary>
        /// Isolated folder for WebView2 cache, cookies, and profile data.
        /// Wiped on application exit to prevent data leakage between sessions.
        /// </summary>
        public const string WebView2UserDataFolder = "SEB_WebView2Data";
    }
}
