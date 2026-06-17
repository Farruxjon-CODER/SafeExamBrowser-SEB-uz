// ============================================================================
// SafeExamBrowser — AdminPasswordDialog.xaml.cs (Dual-Layer Exit Auth)
//
// AUTHENTICATION FLOW (when Ctrl+Shift+Q is pressed):
// ┌─────────────────────────────────────────────────────────────────────────┐
// │  User enters password → clicks "Unlock Exit" (or presses Enter)      │
// │                                                                       │
// │  ┌── Layer 1: Session Password (RAM) ─────────────────────────────┐  │
// │  │  Compare input against SessionManager's in-memory char[].     │  │
// │  │  If match → IsAuthenticated = true → close dialog.            │  │
// │  └────────────────────────────────────────────────────────────────┘  │
// │                          ↓ (no match)                                 │
// │  ┌── Layer 2: Super-Admin SHA-256 Fallback ───────────────────────┐  │
// │  │  Hash input with SHA-256 → compare against hardcoded hash.    │  │
// │  │  If match → IsAuthenticated = true → close dialog.            │  │
// │  └────────────────────────────────────────────────────────────────┘  │
// │                          ↓ (no match)                                 │
// │  Show "Incorrect password" → clear field → let user retry.           │
// │                                                                       │
// │  On success: SessionManager.SecureWipe() zeroes the RAM password.    │
// └─────────────────────────────────────────────────────────────────────────┘
//
// SECURITY NOTES:
// - PasswordBox is used (masked input) to prevent shoulder-surfing.
// - SessionManager.VerifyExitPassword() uses constant-time comparison
//   for both layers to mitigate timing side-channel attacks.
// - On successful authentication, the RAM password is securely wiped
//   so it cannot be recovered via memory forensics post-exit.
// ============================================================================

using System.Windows;
using System.Windows.Input;

namespace SafeExamBrowser
{
    public partial class AdminPasswordDialog : Window
    {
        /// <summary>
        /// True if the correct password was entered on either layer.
        /// Read by MainWindow to decide whether to authorize shutdown.
        /// </summary>
        public bool IsAuthenticated { get; private set; } = false;

        public AdminPasswordDialog()
        {
            InitializeComponent();

            // Auto-focus the password field when the dialog opens
            Loaded += (s, e) => PasswordField.Focus();
        }

        // ════════════════════════════════════════════════════════════════
        // EVENT HANDLERS
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Allow pressing Enter to submit, Escape to cancel.
        /// </summary>
        private void PasswordField_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                ValidatePassword();
            }
            else if (e.Key == Key.Escape)
            {
                DialogResult = false;
                Close();
            }
        }

        private void UnlockButton_Click(object sender, RoutedEventArgs e)
        {
            ValidatePassword();
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }

        // ════════════════════════════════════════════════════════════════
        // DUAL-LAYER PASSWORD VALIDATION
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Validates the entered password against both authentication layers:
        ///   Layer 1: Session password in RAM (set by teacher at startup).
        ///   Layer 2: Super-Admin SHA-256 fallback (hardcoded hash).
        ///   
        /// If either layer matches, the dialog closes with success and
        /// the RAM password is securely wiped from memory.
        /// </summary>
        private void ValidatePassword()
        {
            string entered = PasswordField.Password;

            // ── Empty input guard ───────────────────────────────────
            if (string.IsNullOrEmpty(entered))
            {
                ShowFailure("Iltimos, parolni kiriting.");
                return;
            }

            // ── Dual-Layer Validation via SessionManager ────────────
            // SessionManager.VerifyExitPassword() checks:
            //   1. Does 'entered' match the session password in RAM?
            //   2. Does SHA-256(entered) match the Super-Admin hash?
            // Returns true if EITHER layer succeeds.
            if (SessionManager.VerifyExitPassword(entered))
            {
                // ── Authentication SUCCEEDED ────────────────────────
                IsAuthenticated = true;

                // Securely wipe the session password from RAM.
                // After this call, the char[] is zeroed and set to null.
                // The Super-Admin hash remains (it's a constant, not wiped).
                SessionManager.SecureWipe();

                // Clear the PasswordBox to remove plaintext from WPF buffer
                PasswordField.Clear();

                DialogResult = true;
                Close();
            }
            else
            {
                // ── Authentication FAILED ───────────────────────────
                ShowFailure("Parol noto'g'ri. Kirish rad etildi.");
            }
        }

        /// <summary>
        /// Displays a failure message, clears the password field,
        /// and re-focuses it for the next attempt.
        /// </summary>
        private void ShowFailure(string message)
        {
            MessageBox.Show(
                message,
                "Autentifikatsiya muvaffaqiyatsiz",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);

            PasswordField.Clear();
            PasswordField.Focus();
        }
    }
}
