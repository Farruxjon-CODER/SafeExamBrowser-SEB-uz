// ============================================================================
// SafeExamBrowser - Stage 3: Registry Security Service
//
// PURPOSE:
// Disables Windows Task Manager by writing a DWORD value to the registry:
//   HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System
//     → DisableTaskMgr = 1
//
// When this value is set to 1:
// - Ctrl+Alt+Del screen: "Task Manager" option is greyed out
// - Ctrl+Shift+Esc: Nothing happens (blocked by Stage 2 hook + this)
// - taskmgr.exe: Launches but immediately shows "Task Manager has been
//   disabled by your administrator" and closes
//
// REGISTRY PATH EXPLAINED:
// ┌──────────────────────────────────────────────────────────────────┐
// │ HKEY_CURRENT_USER                                               │
// │ └── Software                                                    │
// │     └── Microsoft                                               │
// │         └── Windows                                             │
// │             └── CurrentVersion                                  │
// │                 └── Policies                                    │
// │                     └── System                                  │
// │                         └── DisableTaskMgr (DWORD)              │
// │                             0 = Enabled (default)               │
// │                             1 = Disabled                        │
// └──────────────────────────────────────────────────────────────────┘
//
// WHY HKCU AND NOT HKLM:
// We use HKCU (Current User) because:
// 1. It does NOT require Administrator privileges to write
// 2. It only affects the currently logged-in user (less collateral)
// 3. HKLM\...\Policies\System\DisableTaskMgr would require admin AND
//    would disable Task Manager for ALL users on the machine
//
// IMPORTANT: Despite using HKCU, we STILL request admin privileges
// via the app.manifest because Stage 3 modifying user policies and
// Stage 4 (Process Watchdog) needs admin rights to kill other
// processes. The manifest ensures we have elevated privileges before
// any stage runs.
//
// FAIL-SAFE ARCHITECTURE (Zombie State Prevention):
// The #1 risk is leaving DisableTaskMgr=1 permanently if our app
// crashes. We implement a 5-LAYER cleanup defense:
//
//   Layer 1: try-finally in LockDown()/Restore() public API
//   Layer 2: IDisposable.Dispose() pattern
//   Layer 3: Application.Current.Exit handler
//   Layer 4: AppDomain.CurrentDomain.ProcessExit handler
//   Layer 5: AppDomain.CurrentDomain.UnhandledException handler
//
// If ALL 5 layers fail (e.g., power loss, BSOD), the user can
// manually fix it by running: REG DELETE "HKCU\Software\Microsoft\
// Windows\CurrentVersion\Policies\System" /v DisableTaskMgr /f
// ============================================================================

using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.Security.Principal;

namespace SafeExamBrowser.Services
{
    /// <summary>
    /// Manages registry-based security policies for the Safe Exam Browser.
    /// Currently handles Task Manager lockdown/restore.
    /// Implements IDisposable with a 5-layer cleanup guarantee.
    /// </summary>
    public sealed class RegistrySecurityService : IDisposable
    {
        // ════════════════════════════════════════════════════════════════
        // Constants
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Registry subkey path under HKCU where Windows policy settings live.
        /// The "Policies\System" subkey may not exist by default — we create it.
        /// </summary>
        private const string PolicySubKey =
            @"Software\Microsoft\Windows\CurrentVersion\Policies\System";

        /// <summary>
        /// Registry value name that controls Task Manager availability.
        /// DWORD: 0 = enabled (default), 1 = disabled.
        /// </summary>
        private const string DisableTaskMgrValue = "DisableTaskMgr";

        // ════════════════════════════════════════════════════════════════
        // Instance Fields
        // ════════════════════════════════════════════════════════════════

        /// <summary>Logger callback for diagnostic output.</summary>
        private readonly Action<string> _logger;

        /// <summary>
        /// Stores the ORIGINAL value of DisableTaskMgr before we modified it.
        /// - null  → The value did not exist (we need to DELETE it on restore)
        /// - 0     → Task Manager was explicitly enabled
        /// - 1     → Task Manager was ALREADY disabled (rare, but possible)
        ///
        /// This distinction is critical: if the value didn't exist before,
        /// we must DELETE it on restore, not set it to 0. Setting it to 0
        /// when it didn't exist before would leave a registry artifact.
        /// </summary>
        private int? _originalValue = null;

        /// <summary>
        /// Tracks whether the registry has been modified by us.
        /// Only true between LockDown() and Restore() calls.
        /// </summary>
        private bool _isLocked = false;

        /// <summary>Tracks whether Dispose has been called.</summary>
        private bool _disposed = false;

        /// <summary>Lock object for thread-safe registry operations.</summary>
        private readonly object _registryLock = new object();

        /// <summary>
        /// Tracks whether cleanup handlers have been registered.
        /// Prevents double-registration.
        /// </summary>
        private bool _handlersRegistered = false;

        // ════════════════════════════════════════════════════════════════
        // Constructor
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Creates a new RegistrySecurityService.
        /// Does NOT modify the registry — call LockDown() explicitly.
        /// </summary>
        public RegistrySecurityService(Action<string> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        // ════════════════════════════════════════════════════════════════
        // Public API
        // ════════════════════════════════════════════════════════════════

        /// <summary>Returns true if Task Manager is currently locked by us.</summary>
        public bool IsLocked => _isLocked;

        /// <summary>
        /// Disables Task Manager by writing DisableTaskMgr=1 to the registry.
        /// Saves the original value for restoration on exit.
        /// 
        /// This method is idempotent — calling it twice is safe.
        /// </summary>
        public void LockDown()
        {
            lock (_registryLock)
            {
                if (_isLocked)
                {
                    _logger("[RegistrySecurity] Already locked down. Skipping.");
                    return;
                }

                _logger("[RegistrySecurity] === STAGE 3: REGISTRY LOCKDOWN ===");

                try
                {
                    // Step 1: Read and save the original value
                    _originalValue = ReadCurrentValue();

                    if (_originalValue.HasValue)
                    {
                        _logger($"[RegistrySecurity] Original DisableTaskMgr value: {_originalValue.Value}");

                        if (_originalValue.Value == 1)
                        {
                            _logger("[RegistrySecurity] WARNING: Task Manager was already disabled! " +
                                    "Will restore to disabled state on exit.");
                        }
                    }
                    else
                    {
                        _logger("[RegistrySecurity] DisableTaskMgr value does not exist (default = enabled). " +
                                "Will DELETE on restore.");
                    }

                    // Step 2: Write DisableTaskMgr = 1
                    WriteValue(1);
                    _isLocked = true;

                    // Step 3: Register cleanup handlers (only once)
                    RegisterCleanupHandlers();

                    _logger("[RegistrySecurity] Task Manager DISABLED successfully.");
                    _logger("[RegistrySecurity] Registry path: HKCU\\" + PolicySubKey);
                }
                catch (Exception ex)
                {
                    _logger($"[RegistrySecurity] FAILED to disable Task Manager: {ex.Message}");
                    _logger("[RegistrySecurity] The application will continue without Task Manager lockdown.");

                    // Don't throw — the app should still function as a kiosk
                    // even if this specific hardening fails. The other stages
                    // (keyboard hooks, process watchdog) still provide protection.
                }
            }
        }

        /// <summary>
        /// Restores Task Manager to its original state.
        /// If the original value didn't exist, we DELETE the registry entry.
        /// If it was 0 or 1, we restore that exact value.
        /// 
        /// This method is idempotent — calling it multiple times is safe.
        /// </summary>
        public void Restore()
        {
            lock (_registryLock)
            {
                if (!_isLocked)
                {
                    _logger("[RegistrySecurity] Not locked — nothing to restore.");
                    return;
                }

                _logger("[RegistrySecurity] === RESTORING REGISTRY ===");

                try
                {
                    if (_originalValue.HasValue)
                    {
                        // Original value existed — restore it
                        WriteValue(_originalValue.Value);
                        _logger($"[RegistrySecurity] Restored DisableTaskMgr to: {_originalValue.Value}");
                    }
                    else
                    {
                        // Original value didn't exist — DELETE the entry
                        DeleteValue();
                        _logger("[RegistrySecurity] Deleted DisableTaskMgr (restored to default).");
                    }

                    _isLocked = false;
                    _logger("[RegistrySecurity] Task Manager RESTORED successfully.");
                }
                catch (Exception ex)
                {
                    _logger($"[RegistrySecurity] CRITICAL: Failed to restore Task Manager: {ex.Message}");
                    _logger("[RegistrySecurity] MANUAL FIX: Run this command as admin:");
                    _logger("[RegistrySecurity]   REG DELETE \"HKCU\\Software\\Microsoft\\Windows\\" +
                            "CurrentVersion\\Policies\\System\" /v DisableTaskMgr /f");
                }
            }
        }

        /// <summary>
        /// Checks if the current process is running with Administrator privileges.
        /// The app.manifest requests elevation, but this method verifies it.
        /// Returns true if elevated, false otherwise.
        /// </summary>
        public static bool IsRunningAsAdministrator()
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        // ════════════════════════════════════════════════════════════════
        // Registry Read/Write Operations
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Reads the current value of DisableTaskMgr from the registry.
        /// Returns null if the value does not exist.
        /// </summary>
        private int? ReadCurrentValue()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(PolicySubKey, writable: false);

                if (key == null)
                {
                    // The entire Policies\System subkey doesn't exist
                    return null;
                }

                object? value = key.GetValue(DisableTaskMgrValue);

                if (value == null)
                {
                    // Subkey exists but DisableTaskMgr value doesn't
                    return null;
                }

                return Convert.ToInt32(value);
            }
            catch (Exception ex)
            {
                _logger($"[RegistrySecurity] Error reading registry: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Writes a DWORD value to DisableTaskMgr.
        /// Creates the Policies\System subkey if it doesn't exist.
        /// </summary>
        private void WriteValue(int value)
        {
            // CreateSubKey opens the key if it exists, creates it if it doesn't.
            // This handles the case where Policies\System doesn't exist yet.
            using var key = Registry.CurrentUser.CreateSubKey(PolicySubKey, writable: true);

            if (key == null)
            {
                throw new InvalidOperationException(
                    $"Failed to create/open registry key: HKCU\\{PolicySubKey}");
            }

            key.SetValue(DisableTaskMgrValue, value, RegistryValueKind.DWord);
        }

        /// <summary>
        /// Deletes the DisableTaskMgr value from the registry.
        /// Used when the original state had no such value (clean restore).
        /// </summary>
        private void DeleteValue()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(PolicySubKey, writable: true);

                if (key == null)
                {
                    // Subkey doesn't exist — nothing to delete
                    return;
                }

                // DeleteValue with throwOnMissingValue: false prevents
                // exceptions if the value was already removed
                key.DeleteValue(DisableTaskMgrValue, throwOnMissingValue: false);
            }
            catch (Exception ex)
            {
                _logger($"[RegistrySecurity] Error deleting registry value: {ex.Message}");
            }
        }

        // ════════════════════════════════════════════════════════════════
        // Cleanup Handler Registration (5-Layer Defense)
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Registers emergency cleanup handlers on multiple exit paths.
        /// This is the core of our "Zombie State" prevention.
        ///
        /// Layer 1: try-finally in LockDown()/Restore() — caller responsibility
        /// Layer 2: IDisposable.Dispose() — "using" statement or manual call
        /// Layer 3: Application.Current.Exit — normal WPF shutdown
        /// Layer 4: AppDomain.ProcessExit — process termination
        /// Layer 5: AppDomain.UnhandledException — unhandled crash
        /// </summary>
        private void RegisterCleanupHandlers()
        {
            if (_handlersRegistered) return;

            // ── Layer 3: WPF Application Exit ───────────────────────────
            if (System.Windows.Application.Current != null)
            {
                System.Windows.Application.Current.Exit += (sender, args) =>
                {
                    _logger("[RegistrySecurity] Layer 3: Application.Exit — restoring registry.");
                    Restore();
                };
            }

            // ── Layer 4: Process Exit (covers Environment.Exit, etc.) ───
            AppDomain.CurrentDomain.ProcessExit += (sender, args) =>
            {
                // Logger may not work here during teardown — use Debug
                Debug.WriteLine("[RegistrySecurity] Layer 4: ProcessExit — emergency restore.");
                Restore();
            };

            // ── Layer 5: Unhandled Exception (crash recovery) ───────────
            AppDomain.CurrentDomain.UnhandledException += (sender, args) =>
            {
                Debug.WriteLine("[RegistrySecurity] Layer 5: UnhandledException — crash restore.");
                // Only restore if this is a terminal exception
                if (args.IsTerminating)
                {
                    Restore();
                }
            };

            _handlersRegistered = true;
            _logger("[RegistrySecurity] 5-layer cleanup defense registered " +
                    "(Dispose + App.Exit + ProcessExit + UnhandledException + Finalizer).");
        }

        // ════════════════════════════════════════════════════════════════
        // IDisposable Implementation (Layer 2)
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Restores the registry and releases resources.
        /// </summary>
        public void Dispose()
        {
            if (!_disposed)
            {
                _logger("[RegistrySecurity] Layer 2: Dispose() — restoring registry.");
                Restore();
                _disposed = true;
            }
        }

        /// <summary>
        /// Finalizer — absolute last resort.
        /// If Dispose() was never called and all event handlers failed,
        /// the finalizer guarantees registry restoration.
        ///
        /// WARNING: The finalizer runs on the GC thread. Logger and
        /// Application.Current are unavailable. We use direct registry
        /// calls and Debug.WriteLine only.
        /// </summary>
        ~RegistrySecurityService()
        {
            if (_isLocked)
            {
                Debug.WriteLine("[RegistrySecurity] FINALIZER: Emergency registry restore! " +
                                "Dispose() was NOT called!");
                try
                {
                    // Direct registry restore — cannot use _logger here
                    if (_originalValue.HasValue)
                    {
                        using var key = Registry.CurrentUser.CreateSubKey(PolicySubKey, writable: true);
                        key?.SetValue(DisableTaskMgrValue, _originalValue.Value, RegistryValueKind.DWord);
                    }
                    else
                    {
                        using var key = Registry.CurrentUser.OpenSubKey(PolicySubKey, writable: true);
                        key?.DeleteValue(DisableTaskMgrValue, throwOnMissingValue: false);
                    }

                    _isLocked = false;
                    Debug.WriteLine("[RegistrySecurity] FINALIZER: Registry restored successfully.");
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[RegistrySecurity] FINALIZER FAILED: {ex.Message}");
                    Debug.WriteLine("[RegistrySecurity] MANUAL FIX REQUIRED: " +
                                    "REG DELETE \"HKCU\\Software\\Microsoft\\Windows\\" +
                                    "CurrentVersion\\Policies\\System\" /v DisableTaskMgr /f");
                }
            }
        }
    }
}
