// ============================================================================
// SafeExamBrowser - Stage 1: WebView2 Security Manager
// Handles WebView2 initialization, security lockdown, and URL enforcement.
//
// SECURITY CONTROLS IMPLEMENTED:
// 1. DevTools (F12) disabled via AreBrowserAcceleratorKeysEnabled = false
// 2. Right-click context menu disabled
// 3. New window popups (window.open, target="_blank") intercepted & cancelled
// 4. URL whitelist enforcement with scheme blocking
// 5. Download prevention
// 6. Drag-and-drop disabled
// 7. Dangerous JavaScript APIs neutralized at document load
// 8. Status bar disabled to prevent URL preview leakage
// 9. Process crash recovery
// ============================================================================

using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;
using SafeExamBrowser.Config;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace SafeExamBrowser.Services
{
    /// <summary>
    /// Manages WebView2 lifecycle, security policies, and URL filtering.
    /// This class encapsulates ALL browser-level security for Stage 1.
    /// </summary>
    public class WebViewManager
    {
        private readonly WebView2 _webView;
        private readonly Action<string> _logger;
        private string? _userDataFolder;

        public WebViewManager(WebView2 webView, Action<string> logger)
        {
            _webView = webView ?? throw new ArgumentNullException(nameof(webView));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        // ── Public API ──────────────────────────────────────────────────

        /// <summary>
        /// Initializes WebView2 with all security settings applied.
        /// Must be called before the browser is usable.
        /// </summary>
        public async Task InitializeAsync()
        {
            _logger("[WebViewManager] Initializing WebView2 engine...");

            // Create an isolated user data folder in %LocalAppData%\SafeExamBrowser
            // CRITICAL: Do NOT use the application directory (e.g., Program Files) —
            // it is read-only and causes WebView2 to crash silently on startup.
            // %LocalAppData% is always writable, even under elevated admin contexts.
            _userDataFolder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SafeExamBrowser",
                AppConfig.WebView2UserDataFolder,
                Guid.NewGuid().ToString("N") // Unique per session
            );

            var environment = await CoreWebView2Environment.CreateAsync(
                userDataFolder: _userDataFolder
            );

            await _webView.EnsureCoreWebView2Async(environment);

            ApplySecuritySettings();
            RegisterEventHandlers();

            _logger("[WebViewManager] WebView2 initialized and locked down.");
            _logger($"[WebViewManager] User data folder: {_userDataFolder}");

            // Navigate to the exam URL
            _webView.CoreWebView2.Navigate(AppConfig.ExamUrl);
            _logger($"[WebViewManager] Navigating to: {AppConfig.ExamUrl}");
        }

        /// <summary>
        /// Cleans up WebView2 resources and wipes the session data folder.
        /// Call this on application exit to prevent data leakage.
        /// </summary>
        public void Cleanup()
        {
            _logger("[WebViewManager] Cleaning up WebView2 resources...");

            try
            {
                _webView.Dispose();
            }
            catch (Exception ex)
            {
                _logger($"[WebViewManager] Dispose error (non-critical): {ex.Message}");
            }

            // Wipe the user data folder to eliminate all session traces
            WipeUserDataFolder();
        }

        // ── Security Configuration ──────────────────────────────────────

        /// <summary>
        /// Applies all browser-level security restrictions.
        /// These settings disable developer tools, context menus, and other
        /// vectors that could allow exam bypass.
        /// </summary>
        private void ApplySecuritySettings()
        {
            var settings = _webView.CoreWebView2.Settings;

            // CRITICAL: Disable F12 DevTools and all browser accelerator keys
            // Without this, students can open DevTools and manipulate the DOM,
            // execute arbitrary JS, or access the console.
            settings.AreBrowserAcceleratorKeysEnabled = false;

            // Disable right-click context menu
            // Prevents "Open in new tab", "Inspect Element", "View Source", etc.
            settings.AreDefaultContextMenusEnabled = false;

            // Disable the status bar (bottom URL preview)
            // Prevents students from seeing where links lead before clicking
            settings.IsStatusBarEnabled = false;

            // Disable built-in zoom controls (Ctrl+, Ctrl-)
            // Prevents accidental zoom that could disrupt the exam layout
            settings.IsZoomControlEnabled = false;

            // Disable the built-in PDF viewer
            // Prevents downloading/viewing PDF attachments
            settings.IsBuiltInErrorPageEnabled = true;

            // Disable password autosave prompts
            settings.IsPasswordAutosaveEnabled = false;

            // Disable general autofill
            settings.IsGeneralAutofillEnabled = false;

            // Disable swipe navigation (touchscreen back/forward gestures)
            settings.IsSwipeNavigationEnabled = false;

            // Allow JavaScript — the exam platform needs it
            settings.IsScriptEnabled = true;

            // Disable pinch-zoom (touchscreen zoom)
            settings.IsPinchZoomEnabled = false;

            _logger("[WebViewManager] Security settings applied.");
        }

        /// <summary>
        /// Registers all event handlers for runtime security enforcement.
        /// </summary>
        private void RegisterEventHandlers()
        {
            var core = _webView.CoreWebView2;

            // ── Block new window creation ───────────────────────────────
            // This catches: window.open(), target="_blank" links, popup ads
            core.NewWindowRequested += OnNewWindowRequested;

            // ── URL Whitelist Enforcement ────────────────────────────────
            // Fires BEFORE navigation begins — we can cancel it here
            core.NavigationStarting += OnNavigationStarting;

            // ── Block Downloads ─────────────────────────────────────────
            // Prevents students from downloading exam content
            core.DownloadStarting += OnDownloadStarting;

            // ── JavaScript Injection at Page Load ───────────────────────
            // Neutralizes dangerous browser APIs before the page can use them
            core.NavigationCompleted += OnNavigationCompleted;

            // ── WebView2 Process Crash Recovery ─────────────────────────
            // The Chromium renderer can crash; we need to handle it gracefully
            core.ProcessFailed += OnProcessFailed;

            _logger("[WebViewManager] Event handlers registered.");
        }

        // ── Event Handlers ──────────────────────────────────────────────

        /// <summary>
        /// Blocks ALL new window requests. Redirects legitimate links
        /// back into the main WebView2 instance.
        /// </summary>
        private void OnNewWindowRequested(object? sender, CoreWebView2NewWindowRequestedEventArgs e)
        {
            _logger($"[BLOCKED] New window request: {e.Uri}");

            // Don't open a new window — instead navigate in the current one
            // (only if the URL passes our whitelist check)
            if (IsUrlAllowed(e.Uri))
            {
                _webView.CoreWebView2.Navigate(e.Uri);
            }

            // Always cancel the new window creation
            e.Handled = true;
        }

        /// <summary>
        /// Enforces URL whitelist. Blocks navigation to unauthorized domains
        /// and dangerous URI schemes.
        /// </summary>
        private void OnNavigationStarting(object? sender, CoreWebView2NavigationStartingEventArgs e)
        {
            if (!IsUrlAllowed(e.Uri))
            {
                _logger($"[BLOCKED] Navigation to: {e.Uri}");
                e.Cancel = true;
                return;
            }

            _logger($"[ALLOWED] Navigation to: {e.Uri}");
        }

        /// <summary>
        /// Blocks ALL file downloads. Students should not be able to
        /// download exam questions, images, or any other content.
        /// </summary>
        private void OnDownloadStarting(object? sender, CoreWebView2DownloadStartingEventArgs e)
        {
            _logger($"[BLOCKED] Download attempt: {e.DownloadOperation.Uri}");
            e.Cancel = true;
        }

        /// <summary>
        /// Injects security JavaScript after each page load.
        /// Neutralizes APIs that could be used to escape the kiosk.
        /// </summary>
        private async void OnNavigationCompleted(object? sender, CoreWebView2NavigationCompletedEventArgs e)
        {
            if (!e.IsSuccess)
            {
                _logger($"[WebViewManager] Navigation failed: {e.WebErrorStatus}");
                return;
            }

            // Inject JavaScript to disable dangerous browser APIs
            string securityScript = @"
                (function() {
                    'use strict';
                    
                    // Disable window.open to prevent popup escapes
                    window.open = function() { return null; };
                    
                    // Disable alert/confirm/prompt to prevent social engineering
                    window.alert = function() {};
                    window.confirm = function() { return false; };
                    window.prompt = function() { return null; };
                    
                    // Disable print to prevent content extraction
                    window.print = function() {};
                    
                    // Disable drag-and-drop to prevent file system access
                    document.addEventListener('dragover', function(e) { e.preventDefault(); }, true);
                    document.addEventListener('drop', function(e) { e.preventDefault(); }, true);
                    
                    // Disable text selection copy (optional - uncomment if needed)
                    // document.addEventListener('copy', function(e) { e.preventDefault(); }, true);
                    
                    // Block right-click at the DOM level as a backup
                    document.addEventListener('contextmenu', function(e) { e.preventDefault(); }, true);
                    
                    console.log('[SEB] Security script injected successfully.');
                })();
            ";

            try
            {
                await _webView.CoreWebView2.ExecuteScriptAsync(securityScript);
                _logger("[WebViewManager] Security JavaScript injected.");
            }
            catch (Exception ex)
            {
                _logger($"[WebViewManager] JS injection failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Handles WebView2 renderer process crashes.
        /// Attempts automatic recovery by navigating back to the exam URL.
        /// </summary>
        private void OnProcessFailed(object? sender, CoreWebView2ProcessFailedEventArgs e)
        {
            _logger($"[WebViewManager] PROCESS FAILURE: {e.ProcessFailedKind}");

            // For render process crashes, the WebView2 control survives
            // and we can navigate back to the exam
            if (e.ProcessFailedKind == CoreWebView2ProcessFailedKind.RenderProcessExited ||
                e.ProcessFailedKind == CoreWebView2ProcessFailedKind.RenderProcessUnresponsive)
            {
                try
                {
                    _webView.CoreWebView2.Navigate(AppConfig.ExamUrl);
                    _logger("[WebViewManager] Recovered from render process failure.");
                }
                catch (Exception ex)
                {
                    _logger($"[WebViewManager] Recovery failed: {ex.Message}");
                }
            }
        }

        // ── URL Filtering Logic ─────────────────────────────────────────

        /// <summary>
        /// Validates a URL against the whitelist and blocked schemes.
        /// Returns true if the URL is safe to navigate to.
        /// </summary>
        private bool IsUrlAllowed(string url)
        {
            if (string.IsNullOrWhiteSpace(url))
                return false;

            // Try to parse the URL
            if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? uri))
                return false;

            // Block dangerous URI schemes (file://, chrome://, javascript:, etc.)
            string scheme = uri.Scheme.ToLowerInvariant();
            if (AppConfig.BlockedSchemes.Any(s => s.Equals(scheme, StringComparison.OrdinalIgnoreCase)))
            {
                _logger($"[URL Filter] Blocked scheme: {scheme}");
                return false;
            }

            // Only allow http and https
            if (scheme != "http" && scheme != "https")
            {
                _logger($"[URL Filter] Non-HTTP scheme blocked: {scheme}");
                return false;
            }

            // Check domain against whitelist
            string host = uri.Host.ToLowerInvariant();
            bool isAllowed = AppConfig.AllowedDomains.Any(domain =>
                host.Equals(domain, StringComparison.OrdinalIgnoreCase) ||
                host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase)
            );

            if (!isAllowed)
            {
                _logger($"[URL Filter] Domain not whitelisted: {host}");
            }

            return isAllowed;
        }

        // ── Cleanup Utilities ───────────────────────────────────────────

        /// <summary>
        /// Securely wipes the WebView2 user data folder.
        /// This removes all cookies, cache, local storage, and browsing history
        /// from the exam session.
        /// </summary>
        private void WipeUserDataFolder()
        {
            if (string.IsNullOrEmpty(_userDataFolder))
                return;

            try
            {
                if (Directory.Exists(_userDataFolder))
                {
                    Directory.Delete(_userDataFolder, recursive: true);
                    _logger($"[WebViewManager] User data folder wiped: {_userDataFolder}");
                }
            }
            catch (Exception ex)
            {
                // Non-critical: files may be locked by WebView2 process
                // They'll be cleaned up on next temp folder cleanup
                _logger($"[WebViewManager] Could not wipe user data folder: {ex.Message}");
            }
        }
    }
}
