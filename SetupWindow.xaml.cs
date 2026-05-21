// ============================================================================
// SafeExamBrowser — SetupWindow.xaml.cs (Pre-boot Session Password)
//
// LIFECYCLE:
//   1. Teacher launches the app → this window appears (OS is NOT locked).
//   2. Teacher enters + confirms a one-time exit password.
//   3. Teacher clicks "Lock & Start Exam":
//      a) Password is stored in RAM via SessionManager.SetSessionPassword().
//      b) This window closes.
//      c) MainWindow opens → all lockdown stages (1-4) activate.
//
// VALIDATION RULES:
//   - Password must be at least 4 characters.
//   - Both fields must match.
//   - The "Lock & Start Exam" button is disabled until both rules pass.
//
// SECURITY NOTES:
//   - PasswordBox is used (not TextBox) to prevent shoulder-surfing.
//   - The password string is handed to SessionManager, which stores it
//     as char[] for deterministic memory wiping.
// ============================================================================

using System;
using System.Windows;

namespace SafeExamBrowser
{
    public partial class SetupWindow : Window
    {
        // ── Minimum password length for session passwords ────────────
        private const int MinPasswordLength = 4;

        public SetupWindow()
        {
            InitializeComponent();

            // Auto-focus the first password field on load
            Loaded += (s, e) => PasswordField.Focus();
        }

        // ════════════════════════════════════════════════════════════════
        // REAL-TIME VALIDATION
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Called whenever either PasswordBox content changes.
        /// Performs live validation and enables/disables the Lock button.
        /// </summary>
        private void PasswordField_PasswordChanged(object sender, RoutedEventArgs e)
        {
            string password = PasswordField.Password;
            string confirm  = ConfirmPasswordField.Password;

            // ── Rule 1: Minimum length ──────────────────────────────
            if (password.Length < MinPasswordLength)
            {
                ValidationMessage.Text = $"Password must be at least {MinPasswordLength} characters.";
                ValidationMessage.Foreground = new System.Windows.Media.SolidColorBrush(
                    (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#e94560"));
                LockButton.IsEnabled = false;
                return;
            }

            // ── Rule 2: Fields must match ───────────────────────────
            if (password != confirm)
            {
                ValidationMessage.Text = "Passwords do not match.";
                ValidationMessage.Foreground = new System.Windows.Media.SolidColorBrush(
                    (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#e94560"));
                LockButton.IsEnabled = false;
                return;
            }

            // ── All rules passed ────────────────────────────────────
            ValidationMessage.Text = "✓ Passwords match. Ready to lock.";
            ValidationMessage.Foreground = new System.Windows.Media.SolidColorBrush(
                (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#4ecca3"));
            LockButton.IsEnabled = true;
        }

        // ════════════════════════════════════════════════════════════════
        // LOCK & START EXAM
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Stores the session password in RAM, opens MainWindow (which
        /// activates all lockdown stages), and closes this setup window.
        /// </summary>
        private void LockButton_Click(object sender, RoutedEventArgs e)
        {
            string password = PasswordField.Password;

            // ── Final safety check (defense-in-depth) ───────────────
            if (string.IsNullOrEmpty(password) || password.Length < MinPasswordLength)
            {
                MessageBox.Show(
                    "Please enter a valid password before proceeding.",
                    "Validation Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            if (password != ConfirmPasswordField.Password)
            {
                MessageBox.Show(
                    "Passwords do not match. Please re-enter.",
                    "Validation Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            try
            {
                // ── Store password in secure RAM variable ───────────
                SessionManager.SetSessionPassword(password);

                // ── Clear the PasswordBox controls immediately ──────
                // This removes the plaintext from WPF's internal buffer.
                PasswordField.Clear();
                ConfirmPasswordField.Clear();

                // ── Launch MainWindow (triggers full lockdown) ──────
                var mainWindow = new MainWindow();
                mainWindow.Show();

                // ── Close this setup window ─────────────────────────
                // MainWindow is now the only window; lockdown is active.
                Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Failed to initialize session:\n\n{ex.Message}",
                    "Critical Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }
    }
}
