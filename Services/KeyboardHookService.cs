// ============================================================================
// SafeExamBrowser - Stage 2: Low-Level Keyboard Hook Service
//
// PURPOSE:
// Installs a WH_KEYBOARD_LL hook via Win32 API (SetWindowsHookEx) to
// intercept and block system-level keyboard shortcuts BEFORE the OS
// processes them. This prevents students from escaping the kiosk via
// Alt+Tab, Win key, Alt+F4, etc.
//
// HOW WH_KEYBOARD_LL WORKS:
// ┌───────────────┐    ┌──────────────────┐    ┌──────────────┐
// │ Physical Key  │───>│ Windows Kernel    │───>│ Our Hook     │──> Block/Allow
// │ Press Event   │    │ (Raw Input Thread)│    │ (LowLevelKbP)│
// └───────────────┘    └──────────────────┘    └──────────────┘
//
// The hook runs in the context of the thread that installed it. Windows
// sends WM_KEYBOARD_LL messages to a callback (LowLevelKeyboardProc)
// BEFORE the target application receives the keystroke. By returning a
// non-zero value from the callback, we consume the keystroke entirely —
// the OS never processes it.
//
// WHY Ctrl+Alt+Del CANNOT BE BLOCKED HERE:
// Ctrl+Alt+Del is intercepted by the Windows kernel (csrss.exe) via the
// Secure Attention Sequence (SAS). This is a hardware-level interrupt
// processed at Ring 0 — no user-mode hook can intercept it. It's a
// deliberate Windows security feature (anti-trojan protection).
// We defer Ctrl+Alt+Del mitigation to Stage 3 (Registry: DisableTaskMgr).
//
// GC SAFETY (CallbackOnCollectedDelegate Prevention):
// The LowLevelKeyboardProc delegate is stored as a STATIC field.
// This guarantees the GC will NEVER collect it while the AppDomain is
// alive, because static fields are GC roots. Without this, the GC could
// collect the delegate while the OS still holds a pointer to it, causing
// an AccessViolationException or a "CallbackOnCollectedDelegate" MDA.
//
// GRACEFUL UNHOOKING:
// We register handlers on both Application.Current.Exit AND
// AppDomain.CurrentDomain.ProcessExit to guarantee cleanup even if
// the process is terminated abnormally. Double-unhook is safe because
// we null-check the handle.
// ============================================================================

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SafeExamBrowser.Services
{
    /// <summary>
    /// Installs and manages a system-wide low-level keyboard hook to block
    /// OS-level escape shortcuts. This service is completely independent
    /// of Stage 1 and can be enabled/disabled without affecting the UI.
    /// </summary>
    public sealed class KeyboardHookService : IDisposable
    {
        // ════════════════════════════════════════════════════════════════
        // Win32 API Constants
        // ════════════════════════════════════════════════════════════════

        /// <summary>Hook type: Low-level keyboard hook (global, no DLL injection needed).</summary>
        private const int WH_KEYBOARD_LL = 13;

        /// <summary>Keystroke message: key pressed down.</summary>
        private const int WM_KEYDOWN = 0x0100;

        /// <summary>Keystroke message: key released.</summary>
        private const int WM_KEYUP = 0x0101;

        /// <summary>System keystroke: key pressed while Alt is held.</summary>
        private const int WM_SYSKEYDOWN = 0x0104;

        /// <summary>System keystroke: key released while Alt was held.</summary>
        private const int WM_SYSKEYUP = 0x0105;

        /// <summary>Flag in KBDLLHOOKSTRUCT.flags indicating Alt key is pressed.</summary>
        private const int LLKHF_ALTDOWN = 0x20;

        // ── Virtual Key Codes ───────────────────────────────────────────
        private const int VK_TAB       = 0x09;
        private const int VK_ESCAPE    = 0x1B;
        private const int VK_F4        = 0x73;
        private const int VK_F12       = 0x7B;  // F12 key (emergency kill switch)
        private const int VK_LWIN      = 0x5B;  // Left Windows key
        private const int VK_RWIN      = 0x5C;  // Right Windows key

        // ════════════════════════════════════════════════════════════════
        // Win32 API P/Invoke Declarations
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Delegate signature for the low-level keyboard procedure.
        /// Must match the LowLevelKeyboardProc callback signature exactly.
        /// </summary>
        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

        /// <summary>
        /// Installs a hook procedure into the Windows hook chain.
        /// For WH_KEYBOARD_LL, the hook is global and does NOT require a DLL.
        /// </summary>
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(
            int idHook,
            LowLevelKeyboardProc lpfn,
            IntPtr hMod,
            uint dwThreadId  // 0 = all threads (global hook)
        );

        /// <summary>
        /// Removes a previously installed hook from the hook chain.
        /// </summary>
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        /// <summary>
        /// Passes the hook information to the next hook in the chain.
        /// MUST be called for any keystroke we choose NOT to block.
        /// </summary>
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CallNextHookEx(
            IntPtr hhk,
            int nCode,
            IntPtr wParam,
            IntPtr lParam
        );

        /// <summary>
        /// Retrieves a module handle for the specified module.
        /// Used to get the handle of the current process module.
        /// </summary>
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string? lpModuleName);

        /// <summary>
        /// Retrieves the state of a specific key (pressed or not).
        /// Used to check modifier key states (Ctrl, Shift) during hook callbacks.
        /// </summary>
        [DllImport("user32.dll")]
        private static extern short GetAsyncKeyState(int vKey);

        // Virtual key codes for modifier state checks
        private const int VK_CONTROL = 0x11;
        private const int VK_SHIFT   = 0x10;
        private const int VK_MENU    = 0x12;  // Alt key

        // ════════════════════════════════════════════════════════════════
        // KBDLLHOOKSTRUCT - The data structure passed to our hook callback
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Contains information about a low-level keyboard input event.
        /// Windows fills this structure and passes a pointer to it in lParam.
        ///
        /// Layout:
        /// - vkCode:      The virtual-key code (e.g., VK_TAB = 0x09)
        /// - scanCode:    Hardware scan code of the key
        /// - flags:       Bit field — bit 5 (LLKHF_ALTDOWN) = Alt is held
        /// - time:        Timestamp of the event
        /// - dwExtraInfo: Extra info associated with the message
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        private struct KBDLLHOOKSTRUCT
        {
            public int vkCode;
            public int scanCode;
            public int flags;
            public int time;
            public IntPtr dwExtraInfo;
        }

#if DEBUG
        // ════════════════════════════════════════════════════════════════
        // Emergency Kill Switch (Static — survives all instance state)
        // DEBUG-ONLY: This entire block is stripped from Release builds
        // via preprocessor directives. The IL will not contain any trace
        // of this property or the kill switch logic in production.
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Static action invoked when Ctrl+Shift+Alt+F12 is detected.
        /// This is set by MainWindow during startup and performs:
        ///   1. Registry restore (direct, no UI)
        ///   2. Keyboard unhook (immediate)
        ///   3. Environment.Exit(0) (bypasses all WPF)
        ///
        /// It is STATIC so it works even if the KeyboardHookService
        /// instance is in a corrupted state. The hook callback reads
        /// this directly without going through any instance fields.
        ///
        /// SECURITY: Conditionally compiled — excluded from Release builds.
        /// </summary>
        public static Action? EmergencyShutdown { get; set; }
#endif

        // ════════════════════════════════════════════════════════════════
        // Instance Fields
        // ════════════════════════════════════════════════════════════════

        /// <summary>Handle returned by SetWindowsHookEx. IntPtr.Zero = not installed.</summary>
        private IntPtr _hookHandle = IntPtr.Zero;

        /// <summary>
        /// CRITICAL: Static reference to the delegate to prevent GC collection.
        ///
        /// When we pass a delegate to SetWindowsHookEx, the OS stores a raw
        /// function pointer. The .NET GC has no knowledge of this unmanaged
        /// reference. If the delegate instance is eligible for collection
        /// (no managed references), the GC WILL collect it. The next time
        /// the OS calls the hook, it jumps to freed memory → crash.
        ///
        /// By storing the delegate in a static field, it becomes a GC root
        /// and will NEVER be collected while the AppDomain is alive.
        /// </summary>
        private static LowLevelKeyboardProc? _hookCallbackDelegate;

        /// <summary>Logger callback for diagnostic output.</summary>
        private readonly Action<string> _logger;

        /// <summary>Tracks whether Dispose has been called.</summary>
        private bool _disposed = false;

        /// <summary>Lock object for thread-safe hook/unhook operations.</summary>
        private readonly object _hookLock = new object();

        // ════════════════════════════════════════════════════════════════
        // Constructor
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Creates a new KeyboardHookService.
        /// Does NOT install the hook — call Install() explicitly.
        /// </summary>
        /// <param name="logger">Callback for diagnostic logging.</param>
        public KeyboardHookService(Action<string> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        // ════════════════════════════════════════════════════════════════
        // Public API
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Returns true if the hook is currently installed and active.
        /// </summary>
        public bool IsInstalled => _hookHandle != IntPtr.Zero;

        /// <summary>
        /// Installs the low-level keyboard hook.
        /// After this call, all blocked key combinations will be intercepted
        /// system-wide, regardless of which application has focus.
        /// </summary>
        /// <exception cref="InvalidOperationException">
        /// Thrown if the hook is already installed.
        /// </exception>
        public void Install()
        {
            lock (_hookLock)
            {
                if (_hookHandle != IntPtr.Zero)
                {
                    _logger("[KeyboardHook] Hook is already installed. Skipping.");
                    return;
                }

                _logger("[KeyboardHook] Installing WH_KEYBOARD_LL hook...");

                // Store the delegate in a STATIC field to prevent GC collection.
                // This is the single most important line for stability.
                _hookCallbackDelegate = HookCallback;

                // Get the module handle of the current process.
                // For WH_KEYBOARD_LL, Windows requires a valid module handle
                // even though the hook doesn't need DLL injection.
                using var currentProcess = Process.GetCurrentProcess();
                using var mainModule = currentProcess.MainModule;
                IntPtr moduleHandle = GetModuleHandle(mainModule?.ModuleName);

                // Install the hook. dwThreadId = 0 means global (all threads).
                _hookHandle = SetWindowsHookEx(
                    WH_KEYBOARD_LL,
                    _hookCallbackDelegate,
                    moduleHandle,
                    0  // Global hook
                );

                if (_hookHandle == IntPtr.Zero)
                {
                    int errorCode = Marshal.GetLastWin32Error();
                    _logger($"[KeyboardHook] FAILED to install hook. Win32 error: {errorCode}");
                    throw new InvalidOperationException(
                        $"SetWindowsHookEx failed with error code {errorCode}. " +
                        "Ensure the application is running with appropriate permissions."
                    );
                }

                // Register emergency cleanup handlers to guarantee unhooking
                // even if the process terminates abnormally.
                RegisterCleanupHandlers();

                _logger("[KeyboardHook] Hook installed successfully.");
                _logger("[KeyboardHook] Blocking: Alt+Tab, Alt+Esc, Alt+F4, " +
                        "Ctrl+Esc, Ctrl+Shift+Esc, LWin, RWin");
            }
        }

        /// <summary>
        /// Removes the keyboard hook and restores normal keyboard behavior.
        /// Safe to call multiple times — subsequent calls are no-ops.
        /// </summary>
        public void Uninstall()
        {
            lock (_hookLock)
            {
                if (_hookHandle == IntPtr.Zero)
                {
                    _logger("[KeyboardHook] Hook is not installed. Nothing to remove.");
                    return;
                }

                _logger("[KeyboardHook] Removing keyboard hook...");

                bool success = UnhookWindowsHookEx(_hookHandle);
                _hookHandle = IntPtr.Zero;

                if (success)
                {
                    _logger("[KeyboardHook] Hook removed successfully. Keyboard restored.");
                }
                else
                {
                    int errorCode = Marshal.GetLastWin32Error();
                    _logger($"[KeyboardHook] WARNING: UnhookWindowsHookEx returned false. " +
                            $"Win32 error: {errorCode}. Hook may have already been removed.");
                }

                // Do NOT null the static delegate here — the OS may still be
                // processing a callback. Let it remain until the AppDomain unloads.
            }
        }

        // ════════════════════════════════════════════════════════════════
        // The Hook Callback — The Core Security Logic
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Called by Windows for EVERY keyboard event system-wide.
        ///
        /// Decision logic:
        /// - Return (IntPtr)1 → BLOCK the keystroke (consumed, OS never sees it)
        /// - Return CallNextHookEx() → ALLOW the keystroke (pass to next hook/app)
        ///
        /// PERFORMANCE NOTE:
        /// Windows enforces a timeout on LowLevel hooks (~300ms by default,
        /// configurable via LowLevelHooksTimeout registry key). If our callback
        /// takes longer than this, Windows REMOVES the hook silently.
        /// Therefore, this callback must be FAST — no I/O, no blocking calls.
        /// </summary>
        private IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            // nCode < 0: Windows says "don't process, just pass along"
            if (nCode < 0)
            {
                return CallNextHookEx(_hookHandle, nCode, wParam, lParam);
            }

            // Only process key-down events (not key-up) to avoid double-logging
            int msg = wParam.ToInt32();
            bool isKeyDown = (msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN);

            if (!isKeyDown)
            {
                // Also block key-up for Windows keys to prevent Start menu
                // from appearing on key release
                if (msg == WM_KEYUP || msg == WM_SYSKEYUP)
                {
                    var kbUp = Marshal.PtrToStructure<KBDLLHOOKSTRUCT>(lParam);
                    if (kbUp.vkCode == VK_LWIN || kbUp.vkCode == VK_RWIN)
                    {
                        return (IntPtr)1; // Block Windows key release too
                    }
                }

                return CallNextHookEx(_hookHandle, nCode, wParam, lParam);
            }

            // Read the KBDLLHOOKSTRUCT from the lParam pointer.
            // This gives us the virtual key code and flags (including Alt state).
            var kb = Marshal.PtrToStructure<KBDLLHOOKSTRUCT>(lParam);

            // Check modifier key states via GetAsyncKeyState.
            // GetAsyncKeyState returns a SHORT where the high bit (0x8000)
            // indicates the key is currently held down.
            bool altHeld = IsKeyDown(VK_MENU) || (kb.flags & LLKHF_ALTDOWN) != 0;
            bool ctrlHeld = IsKeyDown(VK_CONTROL);
            bool shiftHeld = IsKeyDown(VK_SHIFT);

#if DEBUG
            // ── EMERGENCY KILL SWITCH: Ctrl+Shift+Alt+F12 ────────────────
            // DEBUG-ONLY: This entire block is excluded from Release builds.
            // In Release mode, the C# compiler (Roslyn) skips this block
            // entirely — no IL instructions are emitted, making the kill
            // switch impossible to discover via decompilation or reflection.
            //
            // This is the hardware-level fallback. It bypasses ALL UI,
            // ALL dialogs, and ALL WPF machinery. It directly:
            //   1. Restores the registry (re-enables Task Manager)
            //   2. Unhooks the keyboard (restores normal keyboard)
            //   3. Calls Environment.Exit(0) (kills the process)
            //
            // This fires even if WPF is hung, the Dispatcher is blocked,
            // or the UI thread is deadlocked — because the hook callback
            // is invoked by the raw Win32 message pump, not by WPF.
            if (kb.vkCode == VK_F12 && ctrlHeld && shiftHeld && altHeld)
            {
                Debug.WriteLine("[KeyboardHook] *** EMERGENCY KILL SWITCH ACTIVATED ***");
                Debug.WriteLine("[KeyboardHook] Ctrl+Shift+Alt+F12 detected — forcing immediate shutdown.");

                try
                {
                    EmergencyShutdown?.Invoke();
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[KeyboardHook] Emergency shutdown error: {ex.Message}");
                }

                // If EmergencyShutdown didn't call Environment.Exit (shouldn't happen),
                // force it here as an absolute last resort
                Environment.Exit(0);
                return (IntPtr)1; // Unreachable, but compiler requires it
            }
#endif

            // ── Blocked Key Combinations ────────────────────────────────

            // 1. WINDOWS KEYS (Left & Right)
            //    Blocks: Start menu, Win+D (show desktop), Win+E (explorer),
            //    Win+R (run dialog), Win+L (lock screen), Win+Tab, etc.
            if (kb.vkCode == VK_LWIN || kb.vkCode == VK_RWIN)
            {
                LogBlocked("Windows Key");
                return (IntPtr)1;
            }

            // 2. ALT + TAB (Task Switcher)
            //    The Alt key state is encoded in KBDLLHOOKSTRUCT.flags bit 5.
            //    We also check via GetAsyncKeyState as a fallback.
            if (kb.vkCode == VK_TAB && altHeld)
            {
                LogBlocked("Alt+Tab");
                return (IntPtr)1;
            }

            // 3. ALT + ESC (Cycle through windows without the switcher UI)
            if (kb.vkCode == VK_ESCAPE && altHeld)
            {
                LogBlocked("Alt+Esc");
                return (IntPtr)1;
            }

            // 4. ALT + F4 (Close application)
            //    Already partially blocked at the WPF level (Stage 1),
            //    but we block it here at the OS level for defense-in-depth.
            if (kb.vkCode == VK_F4 && altHeld)
            {
                LogBlocked("Alt+F4");
                return (IntPtr)1;
            }

            // 5. CTRL + ESC (Opens Start menu — equivalent to Win key)
            if (kb.vkCode == VK_ESCAPE && ctrlHeld)
            {
                LogBlocked("Ctrl+Esc");
                return (IntPtr)1;
            }

            // 6. CTRL + SHIFT + ESC (Opens Task Manager directly)
            //    Note: This bypasses the Ctrl+Alt+Del screen entirely.
            //    Blocking this here is critical because Stage 3 (Registry)
            //    only disables Task Manager from the Ctrl+Alt+Del screen.
            if (kb.vkCode == VK_ESCAPE && ctrlHeld && shiftHeld)
            {
                LogBlocked("Ctrl+Shift+Esc (Task Manager shortcut)");
                return (IntPtr)1;
            }

            // ── Allow all other keystrokes ──────────────────────────────
            return CallNextHookEx(_hookHandle, nCode, wParam, lParam);
        }

        // ════════════════════════════════════════════════════════════════
        // Helper Methods
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Checks if a key is currently pressed using GetAsyncKeyState.
        /// The high-order bit (0x8000) indicates the key is down.
        /// </summary>
        private static bool IsKeyDown(int virtualKeyCode)
        {
            return (GetAsyncKeyState(virtualKeyCode) & 0x8000) != 0;
        }

        /// <summary>
        /// Logs a blocked keystroke. Uses Debug.WriteLine for speed —
        /// the hook callback must complete within ~300ms or Windows drops it.
        /// No file I/O, no network calls, no allocations beyond the string.
        /// </summary>
        private void LogBlocked(string combination)
        {
            // Intentionally using Debug.WriteLine (no-op in Release builds)
            // instead of the logger callback to minimize callback duration.
            // The logger callback might involve allocations or synchronization.
            Debug.WriteLine($"[KeyboardHook] BLOCKED: {combination}");
        }

        /// <summary>
        /// Registers cleanup handlers on Application.Exit and ProcessExit
        /// to guarantee the hook is removed even during abnormal termination.
        ///
        /// Defense-in-depth:
        /// - Application.Current.Exit: Fires during normal WPF shutdown
        /// - AppDomain.ProcessExit: Fires even if WPF doesn't shut down cleanly
        /// </summary>
        private void RegisterCleanupHandlers()
        {
            // WPF application exit handler
            if (System.Windows.Application.Current != null)
            {
                System.Windows.Application.Current.Exit += (s, e) =>
                {
                    _logger("[KeyboardHook] Application.Exit fired — ensuring hook cleanup.");
                    Uninstall();
                };
            }

            // Process-level exit handler (last resort)
            AppDomain.CurrentDomain.ProcessExit += (s, e) =>
            {
                // Cannot use _logger here — the AppDomain may be tearing down.
                Debug.WriteLine("[KeyboardHook] ProcessExit fired — emergency unhook.");
                Uninstall();
            };

            // Unhandled exception handler (crash recovery)
            // Fixes Bug #1 from safety audit: this was previously missing
            AppDomain.CurrentDomain.UnhandledException += (s, e) =>
            {
                if (e.IsTerminating)
                {
                    Debug.WriteLine("[KeyboardHook] UnhandledException (terminating) — emergency unhook.");
                    Uninstall();
                }
            };

            _logger("[KeyboardHook] Cleanup handlers registered (Application.Exit + ProcessExit + UnhandledException).");
        }

        // ════════════════════════════════════════════════════════════════
        // IDisposable Implementation
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Disposes the service by removing the keyboard hook.
        /// </summary>
        public void Dispose()
        {
            if (!_disposed)
            {
                Uninstall();
                _disposed = true;
            }
        }

        /// <summary>
        /// Finalizer — safety net in case Dispose() is not called.
        /// </summary>
        ~KeyboardHookService()
        {
            // In the finalizer, we can only call Uninstall (unmanaged cleanup).
            // The _logger may already be collected, so we don't use it here.
            if (_hookHandle != IntPtr.Zero)
            {
                Debug.WriteLine("[KeyboardHook] FINALIZER: Emergency unhook (Dispose was not called!)");
                UnhookWindowsHookEx(_hookHandle);
                _hookHandle = IntPtr.Zero;
            }
        }
    }
}
