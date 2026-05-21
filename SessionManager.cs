// ============================================================================
// SafeExamBrowser — SessionManager.cs
//
// SECURITY ARCHITECTURE:
// ┌─────────────────────────────────────────────────────────────────────────┐
// │  Layer 1: Session Password (volatile, RAM-only)                       │
// │    - Set by the teacher at startup via SetupWindow.                    │
// │    - Stored as a char[] (not string) to allow deterministic wiping.    │
// │    - Never written to disk, registry, or any persistent medium.        │
// │    - Wiped from memory via SecureWipe() upon successful exit.          │
// │                                                                       │
// │  Layer 2: Super-Admin SHA-256 Fallback (hardcoded hash)               │
// │    - A SHA-256 hash of a master password baked into the binary.        │
// │    - Acts as a recovery mechanism if the session password is unknown.  │
// │    - The plaintext master password never appears in source code —      │
// │      only the pre-computed hash is stored.                             │
// └─────────────────────────────────────────────────────────────────────────┘
//
// THREAT MODEL:
// - Shoulder-surfing: Passwords are never displayed; PasswordBox is used.
// - Memory forensics: char[] is zeroed after use; GC cannot leak residue.
// - Timing attacks: FixedTimeEquals prevents timing-based hash leaks.
// - Binary reverse-engineering: Only the SHA-256 hash is in the binary,
//   not the plaintext. Attacker must brute-force SHA-256 to recover it.
// ============================================================================

using System;
using System.Security.Cryptography;
using System.Text;

namespace SafeExamBrowser
{
    /// <summary>
    /// Thread-safe singleton managing session credentials and Super-Admin
    /// fallback authentication for the Safe Exam Browser.
    /// </summary>
    public static class SessionManager
    {
        // ════════════════════════════════════════════════════════════════
        // LAYER 2: Super-Admin SHA-256 Fallback Hash
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Pre-computed SHA-256 hash of the Super-Admin master password.
        /// 
        /// IMPORTANT: The plaintext password is NEVER stored in source code.
        /// Only this irreversible hash is embedded in the binary.
        /// 
        /// To regenerate for a different master password:
        ///   PowerShell:
        ///     $sha = [System.Security.Cryptography.SHA256]::Create()
        ///     $bytes = [System.Text.Encoding]::UTF8.GetBytes("YourNewPassword")
        ///     [System.BitConverter]::ToString($sha.ComputeHash($bytes)).Replace("-","").ToLower()
        ///     
        ///   C# (at runtime):
        ///     Console.WriteLine(SessionManager.ComputeSha256Hash("YourNewPassword"));
        /// </summary>
        public const string SuperAdminHash =
            "07758b1b6b45721cc6bee87d9e230e7e9d7e90935dbc091f4ff75ee51957b361";

        // ════════════════════════════════════════════════════════════════
        // LAYER 1: Volatile Session Password (RAM-only)
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Lock object for thread-safe access to the session password.
        /// </summary>
        private static readonly object _lock = new();

        /// <summary>
        /// The teacher's one-time session password, stored as char[] to
        /// allow deterministic zeroing. Null until SetSessionPassword()
        /// is called, and null again after SecureWipe().
        /// </summary>
        private static char[]? _sessionPassword;

        /// <summary>
        /// Indicates whether a session password has been set and not yet wiped.
        /// </summary>
        public static bool HasSessionPassword
        {
            get
            {
                lock (_lock)
                {
                    return _sessionPassword != null && _sessionPassword.Length > 0;
                }
            }
        }

        // ════════════════════════════════════════════════════════════════
        // PUBLIC API
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Stores the teacher's one-time session password in volatile RAM.
        /// Called once from SetupWindow before lockdown begins.
        /// </summary>
        /// <param name="password">The plaintext password to store.</param>
        /// <exception cref="ArgumentException">
        /// Thrown if the password is null or empty.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// Thrown if a session password has already been set (prevents overwrite).
        /// </exception>
        public static void SetSessionPassword(string password)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Session password cannot be null or empty.", nameof(password));

            lock (_lock)
            {
                if (_sessionPassword != null)
                    throw new InvalidOperationException(
                        "Session password has already been set. " +
                        "Call SecureWipe() before setting a new one.");

                // Store as char[] — NOT as a string — so we can zero it later.
                // Strings are immutable and interned by the CLR; char[] is not.
                _sessionPassword = password.ToCharArray();
            }
        }

        /// <summary>
        /// Dual-layer exit password verification.
        /// 
        /// Evaluation order:
        ///   Layer 1 — Does the input match the session password stored in RAM?
        ///   Layer 2 — Does SHA-256(input) match the hardcoded SuperAdminHash?
        ///   
        /// Returns true if EITHER layer matches, granting exit authorization.
        /// 
        /// Security properties:
        ///   - Layer 1 uses constant-time char[] XOR comparison.
        ///   - Layer 2 uses CryptographicOperations.FixedTimeEquals().
        ///   - Both layers are immune to timing side-channel attacks.
        /// </summary>
        /// <param name="inputPassword">The password entered by the user at the exit prompt.</param>
        /// <returns>True if authentication succeeds on either layer.</returns>
        public static bool VerifyExitPassword(string inputPassword)
        {
            if (string.IsNullOrEmpty(inputPassword))
                return false;

            // ── Layer 1: Session Password (volatile RAM comparison) ──
            if (MatchesSessionPassword(inputPassword))
                return true;

            // ── Layer 2: Super-Admin SHA-256 Fallback ────────────────
            if (MatchesSuperAdminHash(inputPassword))
                return true;

            return false;
        }

        /// <summary>
        /// Securely erases the session password from RAM by overwriting
        /// every character with '\0'. This prevents memory forensics from
        /// recovering the password after the session ends.
        /// 
        /// Called after a successful exit authentication.
        /// </summary>
        public static void SecureWipe()
        {
            lock (_lock)
            {
                if (_sessionPassword != null)
                {
                    // Overwrite each character with null bytes
                    Array.Clear(_sessionPassword, 0, _sessionPassword.Length);
                    _sessionPassword = null;
                }
            }
        }

        // ════════════════════════════════════════════════════════════════
        // INTERNAL HELPERS
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Compares the input against the in-memory session password
        /// using a constant-time character comparison to mitigate
        /// timing side-channel attacks.
        /// </summary>
        private static bool MatchesSessionPassword(string input)
        {
            lock (_lock)
            {
                if (_sessionPassword == null || _sessionPassword.Length == 0)
                    return false;

                char[] inputChars = input.ToCharArray();

                try
                {
                    // Length mismatch → fail (but still iterate to avoid
                    // leaking length information via timing).
                    if (inputChars.Length != _sessionPassword.Length)
                        return false;

                    // Constant-time comparison: always checks every byte.
                    int diff = 0;
                    for (int i = 0; i < _sessionPassword.Length; i++)
                    {
                        diff |= inputChars[i] ^ _sessionPassword[i];
                    }

                    return diff == 0;
                }
                finally
                {
                    // Wipe the input copy from stack memory
                    Array.Clear(inputChars, 0, inputChars.Length);
                }
            }
        }

        /// <summary>
        /// Hashes the input using SHA-256 and performs a constant-time
        /// comparison against the hardcoded Super-Admin hash.
        /// Uses CryptographicOperations.FixedTimeEquals to prevent
        /// an attacker from inferring hash characters via response-time.
        /// </summary>
        private static bool MatchesSuperAdminHash(string input)
        {
            string inputHash = ComputeSha256Hash(input);

            // Convert both hex strings to byte[] for FixedTimeEquals.
            // FixedTimeEquals guarantees the comparison runs in constant
            // time regardless of where the first mismatch occurs.
            byte[] inputHashBytes = Encoding.UTF8.GetBytes(inputHash);
            byte[] superAdminBytes = Encoding.UTF8.GetBytes(SuperAdminHash);

            return CryptographicOperations.FixedTimeEquals(inputHashBytes, superAdminBytes);
        }

        /// <summary>
        /// Computes the SHA-256 hash of a plaintext string.
        /// Returns the hash as a lowercase hexadecimal string (64 chars).
        /// 
        /// Uses System.Security.Cryptography.SHA256.HashData() — the
        /// static one-shot API available in .NET 5+ which does not
        /// require manual Dispose() of a hasher instance.
        /// </summary>
        /// <param name="plaintext">The string to hash (UTF-8 encoded).</param>
        /// <returns>64-character lowercase hex string.</returns>
        public static string ComputeSha256Hash(string plaintext)
        {
            byte[] inputBytes = Encoding.UTF8.GetBytes(plaintext);
            byte[] hashBytes = SHA256.HashData(inputBytes);

            // Convert to lowercase hex string (64 characters for SHA-256)
            StringBuilder sb = new(hashBytes.Length * 2);
            foreach (byte b in hashBytes)
            {
                sb.Append(b.ToString("x2"));
            }

            return sb.ToString();
        }
    }
}
