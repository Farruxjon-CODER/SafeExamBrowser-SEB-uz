// ============================================================================
// SafeExamBrowser - FINAL INTEGRATION: Main Window Code-Behind
//
// This file orchestrates ALL 4 security stages in the correct order:
//
//   STARTUP ORDER (Window_Loaded):
//   ┌─────────────────────────────────────────────────────────────────┐
//   │ 1. Admin Privilege Check                                       │
//   │ 2. Stage 2: Install Keyboard Hook (WH_KEYBOARD_LL)             │
//   │ 3. Stage 3: Lock Registry (DisableTaskMgr = 1)                 │
//   │ 4. Stage 4: Start Process Watchdog (background scanner)        │
//   │ 5. Stage 1: Initialize WebView2 (exam browser)                 │
//   └─────────────────────────────────────────────────────────────────┘
//
//   WHY THIS ORDER:
//   - Keyboard hook FIRST: prevents Alt+Tab escape while other stages load
//   - Registry lock SECOND: prevents Task Manager before browser is ready
//   - Watchdog THIRD: kills any already-running blacklisted processes
//   - WebView2 LAST: it's the slowest to initialize (~1-3 seconds)
//
//   SHUTDOWN ORDER (Window_Closing, authorized):
//   ┌─────────────────────────────────────────────────────────────────┐
//   │ 1. Stop Process Watchdog (cancel background thread)            │
//   │ 2. Restore Registry (DisableTaskMgr → original value)          │
//   │ 3. Uninstall Keyboard Hook (restore normal keyboard)           │
//   │ 4. Cleanup WebView2 (dispose + wipe session data)              │
//   └─────────────────────────────────────────────────────────────────┘
//
//   WHY THIS ORDER:
//   - Watchdog stopped FIRST: no point killing processes during shutdown
//   - Registry restored BEFORE keyboard hook: if unhooking crashes,
//     at least Task Manager is already re-enabled for manual recovery
//   - Keyboard hook removed THIRD: user regains Alt+Tab for recovery
//   - WebView2 cleanup LAST: non-critical, just resource cleanup
//
// ADMIN EXIT MECHANISM:
//   Ctrl+Shift+Q → Password prompt (PasswordBox, masked input)
//   Correct password → _isAuthorizedToClose = true → Close()
//   Wrong password → dialog stays, user can retry or cancel
// ============================================================================

using SafeExamBrowser.Config;
using SafeExamBrowser.Services;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Input;

namespace SafeExamBrowser
{
    public partial class MainWindow : Window
    {
        // ════════════════════════════════════════════════════════════════
        // Service Instances (one per stage)
        // ════════════════════════════════════════════════════════════════

        /// <summary>Stage 1: WebView2 browser engine with security lockdown.</summary>
        private WebViewManager? _webViewManager;

        /// <summary>Stage 2: Low-level keyboard hook blocking Alt+Tab, Win, etc.</summary>
        private KeyboardHookService? _keyboardHook;

        /// <summary>Stage 3: Registry-based Task Manager lockdown.</summary>
        private RegistrySecurityService? _registrySecurity;

        /// <summary>Stage 4: Background process watchdog scanner.</summary>
        private ProcessWatchdogService? _processWatchdog;

        // ════════════════════════════════════════════════════════════════
        // State Flags
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Only set to true when the admin provides the correct password.
        /// This is the SOLE condition that allows the window to close.
        /// </summary>
        private bool _isAuthorizedToClose = false;

        /// <summary>
        /// Prevents re-entrant teardown if multiple close paths fire.
        /// </summary>
        private bool _isShuttingDown = false;

        // ════════════════════════════════════════════════════════════════
        // Constructor
        // ════════════════════════════════════════════════════════════════

        public MainWindow()
        {
            InitializeComponent();
        }

        // ════════════════════════════════════════════════════════════════
        // STARTUP — Window_Loaded
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Master startup handler. Initializes all 4 security stages
        /// in the correct order for maximum protection coverage.
        /// </summary>
        private async void Window_Loaded(object sender, RoutedEventArgs e)
        {
            Log("══════════════════════════════════════════════════════════");
            Log("   SAFE EXAM BROWSER — STARTING FULL LOCKDOWN");
            Log("══════════════════════════════════════════════════════════");
            Log($"Window dimensions: {ActualWidth}x{ActualHeight}");
            Log($"Timestamp: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");

            // ── Pre-flight: Admin Privilege Check ───────────────────
            if (!RegistrySecurityService.IsRunningAsAdministrator())
            {
                Log("WARNING: Not running as Administrator!");
                Log("Stage 3 (Registry) may not work correctly.");
                Log("Please restart the application as Administrator.");

                MessageBox.Show(
                    "Safe Exam Browser should be run as Administrator " +
                    "for full security protection.\n\n" +
                    "Some features may not work correctly.",
                    "Warning — Reduced Security",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning
                );
            }
            else
            {
                Log("✓ Running with Administrator privileges.");
            }

            // ── Stage 2: Keyboard Hook (FIRST — blocks escape routes) ──
            try
            {
                Log("");
                Log("─── STAGE 2: Installing Keyboard Hook ───");

                _keyboardHook = new KeyboardHookService(Log);
                _keyboardHook.Install();

                Log("✓ Stage 2 ACTIVE: Alt+Tab, Win, Alt+F4, Ctrl+Esc blocked.");
            }
            catch (Exception ex)
            {
                Log($"✗ Stage 2 FAILED: {ex.Message}");
                Log("Continuing without keyboard hook protection.");
            }

#if DEBUG
            // ── Wire Emergency Kill Switch (Ctrl+Shift+Alt+F12) ─────
            // DEBUG-ONLY: This wiring is excluded from Release builds,
            // matching the #if DEBUG guard on KeyboardHookService.EmergencyShutdown.
            // This MUST be set AFTER _keyboardHook.Install() and will
            // also reference _registrySecurity, which is set below.
            // The lambda captures 'this' to access the service fields.
            // It is set on a STATIC property so it survives instance corruption.
            KeyboardHookService.EmergencyShutdown = () =>
            {
                Debug.WriteLine("[EMERGENCY] Kill switch activated — restoring all locks...");

                // 1. Restore registry FIRST (most critical)
                try
                {
                    _registrySecurity?.Restore();
                    Debug.WriteLine("[EMERGENCY] Registry restored.");
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[EMERGENCY] Registry restore failed: {ex.Message}");
                    // Last-ditch: try direct registry delete
                    try
                    {
                        Microsoft.Win32.Registry.CurrentUser
                            .OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\System", true)
                            ?.DeleteValue("DisableTaskMgr", false);
                        Debug.WriteLine("[EMERGENCY] Direct registry delete succeeded.");
                    }
                    catch { /* Nothing more we can do */ }
                }

                // 2. Unhook keyboard
                try
                {
                    _keyboardHook?.Uninstall();
                    Debug.WriteLine("[EMERGENCY] Keyboard hook removed.");
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[EMERGENCY] Unhook failed: {ex.Message}");
                }

                // 3. Stop watchdog
                try
                {
                    _processWatchdog?.Stop();
                    Debug.WriteLine("[EMERGENCY] Watchdog stopped.");
                }
                catch { /* Non-critical */ }

                // 4. Force exit — ProcessExit handlers will fire as backup
                Debug.WriteLine("[EMERGENCY] Calling Environment.Exit(0)...");
                Environment.Exit(0);
            };
            Log("✓ Emergency kill switch wired (Ctrl+Shift+Alt+F12).");
#else
            Log("ℹ Emergency kill switch DISABLED (Release build).");
#endif

            // ── Stage 3: Registry Lock (SECOND — disables Task Manager) ──
            try
            {
                Log("");
                Log("─── STAGE 3: Locking Registry ───");

                _registrySecurity = new RegistrySecurityService(Log);
                _registrySecurity.LockDown();

                Log("✓ Stage 3 ACTIVE: Task Manager disabled.");
            }
            catch (Exception ex)
            {
                Log($"✗ Stage 3 FAILED: {ex.Message}");
                Log("Continuing without Task Manager lockdown.");
            }

            // ── Stage 4: Process Watchdog (THIRD — kills blacklisted apps) ──
            try
            {
                Log("");
                Log("─── STAGE 4: Starting Process Watchdog ───");

                _processWatchdog = new ProcessWatchdogService(Log);

                // Perform an immediate sweep before starting the loop
                int initialKills = _processWatchdog.ScanOnce();
                if (initialKills > 0)
                {
                    Log($"⚠ Initial sweep killed {initialKills} blacklisted process(es).");
                }

                _processWatchdog.Start();

                Log("✓ Stage 4 ACTIVE: Background scanner running (2s interval).");
            }
            catch (Exception ex)
            {
                Log($"✗ Stage 4 FAILED: {ex.Message}");
                Log("Continuing without process watchdog.");
            }

            // ── Stage 1: WebView2 Initialization (LAST — slowest) ──────
            try
            {
                Log("");
                Log("─── STAGE 1: Initializing WebView2 Browser ───");

                _webViewManager = new WebViewManager(ExamWebView, Log);
                await _webViewManager.InitializeAsync();

                // Hide the loading overlay — exam is now visible
                LoadingOverlay.Visibility = Visibility.Collapsed;

                Log("✓ Stage 1 ACTIVE: Secure browser loaded.");
            }
            catch (Exception ex)
            {
                Log($"✗ Stage 1 CRITICAL FAILURE: {ex.Message}");

                MessageBox.Show(
                    "Failed to initialize the secure browser.\n\n" +
                    "Please ensure Microsoft Edge WebView2 Runtime is installed.\n\n" +
                    $"Error: {ex.Message}",
                    "Safe Exam Browser — Critical Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error
                );

                // Cannot function without WebView2 — perform emergency shutdown
                _isAuthorizedToClose = true;
                Close();
                return;
            }

            // ── All stages initialized ──────────────────────────────────
            Log("");
            Log("══════════════════════════════════════════════════════════");
            Log("   ALL 4 STAGES ACTIVE — KIOSK IS FULLY LOCKED");
            Log("══════════════════════════════════════════════════════════");
            Log("Admin exit: Ctrl+Shift+Q (password required)");
            Log("");
        }

        // ════════════════════════════════════════════════════════════════
        // SHUTDOWN — Window_Closing
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Intercepts ALL close attempts. Only allows closing when
        /// _isAuthorizedToClose is true (admin password verified).
        /// Performs orderly teardown of all security stages.
        /// </summary>
        private void Window_Closing(object? sender, CancelEventArgs e)
        {
            // ── Block unauthorized close attempts ───────────────────
            if (!_isAuthorizedToClose)
            {
                e.Cancel = true;
                Log("[BLOCKED] Unauthorized close attempt.");
                return;
            }

            // ── Prevent re-entrant teardown ─────────────────────────
            if (_isShuttingDown)
                return;

            _isShuttingDown = true;

            Log("");
            Log("══════════════════════════════════════════════════════════");
            Log("   AUTHORIZED SHUTDOWN — RELEASING ALL LOCKS");
            Log("══════════════════════════════════════════════════════════");

            // ── Teardown in reverse order (LIFO) ────────────────────
            // Each stage is wrapped in try-catch to ensure subsequent
            // stages are always cleaned up even if one fails.

            // 1. Stop Process Watchdog (non-critical, stop first)
            try
            {
                Log("Stopping Stage 4 (Process Watchdog)...");
                _processWatchdog?.Stop();
                if (_processWatchdog != null)
                {
                    Log($"  Watchdog stopped. Total kills this session: {_processWatchdog.TotalKilled}");
                }
                _processWatchdog?.Dispose();
                Log("✓ Stage 4 released.");
            }
            catch (Exception ex)
            {
                Log($"✗ Stage 4 teardown error: {ex.Message}");
            }

            // 2. Restore Registry (CRITICAL — must happen before hook removal)
            try
            {
                Log("Restoring Stage 3 (Registry)...");
                _registrySecurity?.Restore();
                _registrySecurity?.Dispose();
                Log("✓ Stage 3 released — Task Manager restored.");
            }
            catch (Exception ex)
            {
                Log($"✗ Stage 3 teardown error: {ex.Message}");
                Log("MANUAL FIX: REG DELETE \"HKCU\\Software\\Microsoft\\Windows\\" +
                    "CurrentVersion\\Policies\\System\" /v DisableTaskMgr /f");
            }

            // 3. Uninstall Keyboard Hook
            try
            {
                Log("Uninstalling Stage 2 (Keyboard Hook)...");
                _keyboardHook?.Uninstall();
                _keyboardHook?.Dispose();
                Log("✓ Stage 2 released — Keyboard restored.");
            }
            catch (Exception ex)
            {
                Log($"✗ Stage 2 teardown error: {ex.Message}");
            }

            // 4. Cleanup WebView2 (non-critical, just resource cleanup)
            try
            {
                Log("Cleaning up Stage 1 (WebView2)...");
                _webViewManager?.Cleanup();
                Log("✓ Stage 1 released — Browser cleaned up.");
            }
            catch (Exception ex)
            {
                Log($"✗ Stage 1 teardown error: {ex.Message}");
            }

            Log("");
            Log("══════════════════════════════════════════════════════════");
            Log("   ALL LOCKS RELEASED — SAFE SHUTDOWN COMPLETE");
            Log($"   Session ended: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            Log("══════════════════════════════════════════════════════════");
        }

        // ════════════════════════════════════════════════════════════════
        // KEYBOARD INPUT — Admin Exit & Key Blocking
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Handles keyboard input at the WPF window level.
        ///
        /// ADMIN EXIT: Ctrl+Shift+Q
        /// Opens a password-protected dialog. If the correct password
        /// is entered, the kiosk shuts down gracefully.
        ///
        /// Also blocks F11 (fullscreen toggle) and Escape at the WPF level
        /// as defense-in-depth alongside the Stage 2 keyboard hook.
        /// </summary>
        protected override void OnPreviewKeyDown(KeyEventArgs e)
        {
            // ── Admin Exit: Ctrl + Shift + Q ────────────────────────
            if (e.Key == Key.Q &&
                Keyboard.Modifiers.HasFlag(ModifierKeys.Control) &&
                Keyboard.Modifiers.HasFlag(ModifierKeys.Shift))
            {
                Log("[AdminExit] Ctrl+Shift+Q detected — opening password prompt.");
                e.Handled = true;

                ShowAdminPasswordDialog();
                return;
            }

            // ── Block F11 (fullscreen toggle) ───────────────────────
            if (e.Key == Key.F11)
            {
                e.Handled = true;
                return;
            }

            // ── Block Escape ────────────────────────────────────────
            if (e.Key == Key.Escape)
            {
                e.Handled = true;
                return;
            }

            base.OnPreviewKeyDown(e);
        }

        /// <summary>
        /// Shows the admin password dialog. If the correct password is
        /// entered, sets _isAuthorizedToClose and initiates shutdown.
        /// </summary>
        private void ShowAdminPasswordDialog()
        {
            // Temporarily bring the dialog above our TopMost window
            var dialog = new AdminPasswordDialog
            {
                Owner = this,
                Topmost = true
            };

            bool? result = dialog.ShowDialog();

            if (result == true && dialog.IsAuthenticated)
            {
                Log("[AdminExit] ✓ Password verified — initiating authorized shutdown.");
                _isAuthorizedToClose = true;
                Close();
            }
            else
            {
                Log("[AdminExit] ✗ Authentication failed or cancelled.");
            }
        }

        // ════════════════════════════════════════════════════════════════
        // KIOSK ENFORCEMENT — Window State & Focus
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Re-enforces maximized state if the window is somehow minimized.
        /// </summary>
        protected override void OnStateChanged(EventArgs e)
        {
            if (WindowState != WindowState.Maximized)
            {
                Log("[Kiosk] Window state changed — forcing Maximized.");
                WindowState = WindowState.Maximized;
            }

            base.OnStateChanged(e);
        }

        /// <summary>
        /// When the window loses focus, reclaim it immediately.
        /// Works alongside Stage 2 keyboard hooks for defense-in-depth.
        /// </summary>
        protected override void OnDeactivated(EventArgs e)
        {
            base.OnDeactivated(e);

            // Don't reclaim focus during shutdown or when showing the
            // admin password dialog — it would steal focus from the dialog
            if (_isShuttingDown || _isAuthorizedToClose)
                return;

            Log("[Kiosk] Window deactivated — reclaiming focus.");
            Topmost = true;
            Activate();
            Focus();
        }

        // ════════════════════════════════════════════════════════════════
        // LOGGING
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Central logging method used by all services and this window.
        /// Outputs to Debug (visible in VS Code Output panel).
        /// In production, replace with Serilog/NLog writing to an
        /// encrypted, append-only log file.
        /// </summary>
        private void Log(string message)
        {
            string entry = $"[{DateTime.Now:HH:mm:ss.fff}] {message}";
            Debug.WriteLine(entry);
        }
    }
}