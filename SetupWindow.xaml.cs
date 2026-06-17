// ============================================================================
// SafeExamBrowser — SetupWindow.xaml.cs (Pre-boot Session Setup)
//
// LIFECYCLE:
//   1. Teacher launches the app → this window appears (OS is NOT locked).
//   2. Teacher enters the exam URL + creates a one-time exit password.
//   3. Teacher clicks "Lock & Start Exam":
//      a) URL is validated and stored in SessionManager.ExamUrl.
//      b) Password is stored in RAM via SessionManager.SetSessionPassword().
//      c) This window closes.
//      d) MainWindow opens → all lockdown stages (1-4) activate.
//
// VALIDATION RULES:
//   - Exam URL must not be empty.
//   - If the URL lacks a scheme, "https://" is auto-prepended
//     (unless it starts with "localhost", which gets "http://").
//   - Password must be at least 4 characters.
//   - Both password fields must match.
//   - The "Lock & Start Exam" button is disabled until ALL rules pass.
//
// SECURITY NOTES:
//   - PasswordBox is used (not TextBox) to prevent shoulder-surfing.
//   - The password string is handed to SessionManager, which stores it
//     as char[] for deterministic memory wiping.
//   - The URL is stored as a plain string — it is not sensitive data.
// ============================================================================

using System;
using System.Windows;
using System.Windows.Controls;

namespace SafeExamBrowser
{
    public partial class SetupWindow : Window
    {
        // ── Minimum password length for session passwords ────────────
        private const int MinPasswordLength = 4;

        public SetupWindow()
        {
            InitializeComponent();

            // Auto-focus the URL field on load (it's the first input now)
            Loaded += (s, e) => UrlTextBox.Focus();
        }

        // ════════════════════════════════════════════════════════════════
        // URL FIELD — Placeholder Behavior
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Hides the watermark placeholder when the user starts typing,
        /// and triggers re-validation of the entire form.
        /// </summary>
        private void UrlTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            // Toggle placeholder visibility
            if (UrlPlaceholder != null)
            {
                UrlPlaceholder.Visibility = string.IsNullOrEmpty(UrlTextBox.Text)
                    ? Visibility.Visible
                    : Visibility.Collapsed;
            }

            // Re-run full form validation
            ValidateForm();
        }

        // ════════════════════════════════════════════════════════════════
        // REAL-TIME VALIDATION
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Called whenever either PasswordBox content changes.
        /// Delegates to the unified form validator.
        /// </summary>
        private void PasswordField_PasswordChanged(object sender, RoutedEventArgs e)
        {
            ValidateForm();
        }

        /// <summary>
        /// Unified form validation. Checks URL + password rules and
        /// enables/disables the Lock button accordingly.
        /// </summary>
        private void ValidateForm()
        {
            string url      = UrlTextBox?.Text?.Trim() ?? "";
            string password = PasswordField?.Password ?? "";
            string confirm  = ConfirmPasswordField?.Password ?? "";

            // ── Rule 1: URL must not be empty ───────────────────────
            if (string.IsNullOrWhiteSpace(url))
            {
                ValidationMessage.Text = "Iltimos, imtihon URL manzilini kiriting.";
                ValidationMessage.Foreground = new System.Windows.Media.SolidColorBrush(
                    (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#e94560"));
                LockButton.IsEnabled = false;
                return;
            }

            // ── Rule 2: Minimum password length ─────────────────────
            if (password.Length < MinPasswordLength)
            {
                ValidationMessage.Text = $"Parol kamida {MinPasswordLength} ta belgidan iborat bo'lishi kerak.";
                ValidationMessage.Foreground = new System.Windows.Media.SolidColorBrush(
                    (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#e94560"));
                LockButton.IsEnabled = false;
                return;
            }

            // ── Rule 3: Passwords must match ────────────────────────
            if (password != confirm)
            {
                ValidationMessage.Text = "Parollar mos kelmaydi.";
                ValidationMessage.Foreground = new System.Windows.Media.SolidColorBrush(
                    (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#e94560"));
                LockButton.IsEnabled = false;
                return;
            }

            // ── All rules passed ────────────────────────────────────
            ValidationMessage.Text = "✓ Qulflash va imtihonni boshlashga tayyor.";
            ValidationMessage.Foreground = new System.Windows.Media.SolidColorBrush(
                (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#4ecca3"));
            LockButton.IsEnabled = true;
        }

        // ════════════════════════════════════════════════════════════════
        // URL NORMALIZATION
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Normalizes a user-provided URL string:
        ///   - Trims whitespace.
        ///   - If it starts with "localhost" (with no scheme), prepends "http://".
        ///   - Otherwise, if no scheme is present, prepends "https://".
        ///   - Validates the result is a well-formed absolute URI.
        /// Returns null if the URL is fundamentally invalid.
        /// </summary>
        private static string? NormalizeUrl(string rawUrl)
        {
            if (string.IsNullOrWhiteSpace(rawUrl))
                return null;

            string url = rawUrl.Trim();

            // Auto-prepend scheme if missing
            if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                // localhost gets http:// (typical for local dev servers)
                if (url.StartsWith("localhost", StringComparison.OrdinalIgnoreCase))
                {
                    url = "http://" + url;
                }
                else
                {
                    url = "https://" + url;
                }
            }

            // Validate the result is a proper absolute URI
            if (Uri.TryCreate(url, UriKind.Absolute, out Uri? validatedUri) &&
                (validatedUri.Scheme == "http" || validatedUri.Scheme == "https"))
            {
                return validatedUri.AbsoluteUri;
            }

            return null;
        }

        // ════════════════════════════════════════════════════════════════
        // LOCK & START EXAM
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Validates inputs, stores the URL and password in RAM,
        /// opens MainWindow (which activates all lockdown stages),
        /// and closes this setup window.
        /// </summary>
        private void LockButton_Click(object sender, RoutedEventArgs e)
        {
            string rawUrl  = UrlTextBox.Text.Trim();
            string password = PasswordField.Password;

            // ── Validate URL ────────────────────────────────────────
            string? normalizedUrl = NormalizeUrl(rawUrl);

            if (normalizedUrl == null)
            {
                MessageBox.Show(
                    "Imtihon URL manzili noto'g'ri.\n\n" +
                    "Iltimos, to'g'ri URL manzilini kiriting, masalan:\n" +
                    "  • https://exam.example.com\n" +
                    "  • localhost:3000",
                    "Noto'g'ri URL",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                UrlTextBox.Focus();
                return;
            }

            // ── Validate Password ───────────────────────────────────
            if (string.IsNullOrEmpty(password) || password.Length < MinPasswordLength)
            {
                MessageBox.Show(
                    "Iltimos, davom etishdan oldin to'g'ri parolni kiriting.",
                    "Tekshirish xatosi",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                PasswordField.Focus();
                return;
            }

            if (password != ConfirmPasswordField.Password)
            {
                MessageBox.Show(
                    "Parollar mos kelmaydi. Iltimos, qaytadan kiriting.",
                    "Tekshirish xatosi",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                ConfirmPasswordField.Focus();
                return;
            }

            try
            {
                // ── Store URL in SessionManager (RAM-only) ──────────
                SessionManager.ExamUrl = normalizedUrl;

                // ── Store password in secure RAM variable ───────────
                SessionManager.SetSessionPassword(password);

                // ── Clear the input controls immediately ────────────
                // This removes plaintext from WPF's internal buffers.
                UrlTextBox.Clear();
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
                    $"Sessiyani ishga tushirib bo'lmadi:\n\n{ex.Message}",
                    "Muhim xatolik",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        // ════════════════════════════════════════════════════════════════
        // CANCEL
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Closes the setup window without starting the exam session.
        /// Since this is the startup window, closing it exits the application.
        /// </summary>
        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
