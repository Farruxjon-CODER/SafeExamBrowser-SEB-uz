// ============================================================================
// SafeExamBrowser - Stage 4: Process Watchdog Service
//
// PURPOSE:
// Continuously scans running processes in the background and forcefully
// terminates any that appear on a configurable blacklist. This prevents
// students from using screen-sharing, remote-access, recording, or
// communication tools during an exam.
//
// HOW IT WORKS:
// ┌─────────────────────────────────────────────────────────────────┐
// │  Background Task (async loop)                                  │
// │                                                                │
// │  while (!cancellationToken.IsCancellationRequested)             │
// │  {                                                             │
// │      foreach (Process p in Process.GetProcesses())             │
// │      {                                                         │
// │          if (blacklist.Contains(p.ProcessName.ToLower()))       │
// │              p.Kill();  // Forceful termination                │
// │      }                                                         │
// │      await Task.Delay(ScanIntervalMs, cancellationToken);      │
// │  }                                                             │
// └─────────────────────────────────────────────────────────────────┘
//
// SYSTEM.DIAGNOSTICS.PROCESS MECHANICS:
// - Process.GetProcesses() calls the Win32 API EnumProcesses() to get
//   a snapshot of all running processes. This returns an array of
//   Process objects with handles to each process.
// - Process.ProcessName reads the executable name WITHOUT the .exe
//   extension (e.g., "AnyDesk" not "AnyDesk.exe").
// - Process.Kill() calls TerminateProcess() via Win32 API, which
//   sends an exit signal the target process cannot intercept or block.
//
// "ACCESS DENIED" HANDLING:
// When our app (even elevated) tries to inspect certain processes,
// we can hit two exceptions:
//
// 1. Win32Exception (Access Denied):
//    Occurs when reading properties of SYSTEM-level processes like
//    csrss.exe, smss.exe, or services running as LOCAL SYSTEM.
//    Even Administrator cannot read all properties of these processes.
//    The OS returns ERROR_ACCESS_DENIED (5).
//
// 2. InvalidOperationException:
//    Occurs when a process exits between GetProcesses() and our
//    inspection — a classic TOCTOU (Time-Of-Check-Time-Of-Use) race.
//    The Process handle becomes invalid mid-iteration.
//
// Both are expected and harmless. Our code wraps each individual
// process inspection in its own try-catch, so one inaccessible
// process never crashes the entire scan loop.
// ============================================================================

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace SafeExamBrowser.Services
{
    /// <summary>
    /// Background service that continuously monitors running processes
    /// and kills any that match a configurable blacklist.
    /// Uses async Task.Delay for CPU-efficient polling.
    /// </summary>
    public sealed class ProcessWatchdogService : IDisposable
    {
        // ════════════════════════════════════════════════════════════════
        // Configuration
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Interval between process scans in milliseconds.
        /// 2000ms (2 seconds) provides responsive detection without
        /// measurable CPU overhead. Process.GetProcesses() takes ~1-5ms
        /// on typical systems, so duty cycle is ~0.25%.
        /// </summary>
        private const int ScanIntervalMs = 2000;

        /// <summary>
        /// Maximum number of consecutive scan failures before the
        /// watchdog logs a critical warning. The loop continues
        /// regardless — this is for monitoring/alerting only.
        /// </summary>
        private const int MaxConsecutiveFailures = 10;

        // ════════════════════════════════════════════════════════════════
        // Blacklist — Process names WITHOUT .exe extension
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Comprehensive blacklist of processes that must be terminated.
        /// Process.ProcessName returns names WITHOUT the .exe extension.
        /// All comparisons are case-insensitive.
        ///
        /// Categories:
        /// - Remote Desktop / Access: AnyDesk, TeamViewer, VNC, RDP, etc.
        /// - Screen Recording: OBS, Bandicam, Camtasia, ShareX, etc.
        /// - Communication: Discord, Telegram, WhatsApp, Zoom, etc.
        /// - Virtual Machines: VMware, VirtualBox (exam in VM = bypass)
        /// - Cheat Tools: Cheat Engine, AutoHotkey, macro recorders
        /// - Browsers: Prevent opening a second browser for searching
        /// </summary>
        private static readonly HashSet<string> DefaultBlacklist = new(
            StringComparer.OrdinalIgnoreCase)
        {
            // ── Remote Desktop & Access ─────────────────────────────
            "anydesk",              // AnyDesk remote access
            "teamviewer",           // TeamViewer
            "teamviewer_service",   // TeamViewer service component
            "tv_w32",               // TeamViewer older versions
            "tv_x64",              // TeamViewer 64-bit
            "vncviewer",            // VNC Viewer
            "tvnviewer",            // TightVNC Viewer
            "winvnc",               // WinVNC Server
            "uvnc_service",         // UltraVNC
            "rustdesk",             // RustDesk open-source remote
            "parsec",               // Parsec remote desktop
            "supremo",              // Supremo remote control
            "ammyyadmin",           // Ammyy Admin
            "radmin",               // Radmin remote admin
            "mstsc",                // Microsoft Remote Desktop Client
            "msrdc",                // Microsoft Remote Desktop (modern)
            "chrome_remote_desktop", // Chrome Remote Desktop

            // ── Screen Recording & Streaming ────────────────────────
            "obs64",                // OBS Studio 64-bit
            "obs32",                // OBS Studio 32-bit
            "obs",                  // OBS (generic)
            "streamlabs",           // Streamlabs OBS
            "bandicam",             // Bandicam recorder
            "bdcam",                // Bandicam capture component
            "camtasia",             // Camtasia recorder
            "camrecorder",          // Camtasia recorder component
            "sharex",               // ShareX screenshot/recording
            "screenpresso",         // Screenpresso
            "loom",                 // Loom screen recording
            "screencastify",        // Screencastify
            "xsplit",               // XSplit Broadcaster
            "xsplitbroadcaster",    // XSplit
            "action",               // Mirillis Action!
            "fraps",                // Fraps recorder
            "dxtory",               // Dxtory video capture
            "medalclient",          // Medal.tv clip recorder

            // ── Communication & Messaging ───────────────────────────
            "discord",              // Discord
            "discordptb",           // Discord Public Test Build
            "discordcanary",        // Discord Canary
            "telegram",             // Telegram Desktop
            "whatsapp",             // WhatsApp Desktop
            "signal",               // Signal Desktop
            "slack",                // Slack
            "skype",                // Skype
            "teams",                // Microsoft Teams (old)
            "ms-teams",             // Microsoft Teams (new)
            "viber",                // Viber
            "zoom",                 // Zoom
            "zoomus",               // Zoom (alternative name)

            // ── Virtual Machine Clients ─────────────────────────────
            "vmware",               // VMware Workstation
            "vmplayer",             // VMware Player
            "virtualbox",           // Oracle VirtualBox
            "virtualboxvm",         // VirtualBox VM window
            "vboxsvc",              // VirtualBox service
            "qemu-system-x86_64",   // QEMU emulator
            "hyperv",               // Hyper-V

            // ── Cheat Tools & Automation ────────────────────────────
            "cheatengine-x86_64",   // Cheat Engine 64-bit
            "cheatengine-i386",     // Cheat Engine 32-bit
            "autohotkey",           // AutoHotkey script engine
            "autohotkey64",         // AutoHotkey 64-bit
            "autoit3",              // AutoIt automation
            "tinytask",             // TinyTask macro recorder

            // ── Alternative Browsers ────────────────────────────────
            "chrome",               // Google Chrome
            "firefox",              // Mozilla Firefox
            "opera",                // Opera Browser
            "brave",                // Brave Browser
            "msedge",               // Microsoft Edge (standalone)
            "vivaldi",              // Vivaldi Browser
            "iexplore",             // Internet Explorer
        };

        // ════════════════════════════════════════════════════════════════
        // Instance Fields
        // ════════════════════════════════════════════════════════════════

        /// <summary>The active blacklist used for scanning.</summary>
        private readonly HashSet<string> _blacklist;

        /// <summary>Logger callback for diagnostic output.</summary>
        private readonly Action<string> _logger;

        /// <summary>Cancellation token source to stop the background loop.</summary>
        private CancellationTokenSource? _cts;

        /// <summary>Reference to the background scanning task.</summary>
        private Task? _scanTask;

        /// <summary>Tracks whether Dispose has been called.</summary>
        private bool _disposed = false;

        /// <summary>Tracks consecutive scan failures for alerting.</summary>
        private int _consecutiveFailures = 0;

        /// <summary>Total number of processes killed during this session.</summary>
        private int _totalKilled = 0;

        /// <summary>
        /// Our own process ID — we must never kill ourselves.
        /// Cached once at construction to avoid repeated lookups.
        /// </summary>
        private readonly int _ownProcessId;

        /// <summary>
        /// Our own process name — excluded from blacklist matching.
        /// </summary>
        private readonly string _ownProcessName;

        // ════════════════════════════════════════════════════════════════
        // Constructor
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Creates a new ProcessWatchdogService with the default blacklist.
        /// Does NOT start scanning — call StartAsync() explicitly.
        /// </summary>
        /// <param name="logger">Callback for diagnostic logging.</param>
        /// <param name="additionalBlacklist">
        /// Optional extra process names to block (merged with defaults).
        /// </param>
        public ProcessWatchdogService(
            Action<string> logger,
            IEnumerable<string>? additionalBlacklist = null)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            // Build the effective blacklist by merging defaults + custom entries
            _blacklist = new HashSet<string>(DefaultBlacklist, StringComparer.OrdinalIgnoreCase);

            if (additionalBlacklist != null)
            {
                foreach (var name in additionalBlacklist)
                {
                    if (!string.IsNullOrWhiteSpace(name))
                        _blacklist.Add(name.Trim());
                }
            }

            // Cache our own identity to avoid self-termination
            using var self = Process.GetCurrentProcess();
            _ownProcessId = self.Id;
            _ownProcessName = self.ProcessName;

            _logger($"[Watchdog] Initialized with {_blacklist.Count} blacklisted process names.");
            _logger($"[Watchdog] Own PID: {_ownProcessId} ({_ownProcessName}) — excluded from scanning.");
        }

        // ════════════════════════════════════════════════════════════════
        // Public API
        // ════════════════════════════════════════════════════════════════

        /// <summary>Returns true if the watchdog is actively scanning.</summary>
        public bool IsRunning => _scanTask != null &&
                                 !_scanTask.IsCompleted &&
                                 _cts != null &&
                                 !_cts.IsCancellationRequested;

        /// <summary>Total processes killed during this session.</summary>
        public int TotalKilled => _totalKilled;

        /// <summary>
        /// Starts the background process scanning loop.
        /// The loop runs asynchronously using Task.Run and polls
        /// every ScanIntervalMs milliseconds.
        /// </summary>
        public void Start()
        {
            if (_scanTask != null && !_scanTask.IsCompleted)
            {
                _logger("[Watchdog] Already running. Skipping start.");
                return;
            }

            _logger("[Watchdog] === STAGE 4: PROCESS WATCHDOG STARTING ===");
            _logger($"[Watchdog] Scan interval: {ScanIntervalMs}ms");

            _cts = new CancellationTokenSource();
            var token = _cts.Token;

            // Launch the scan loop on a ThreadPool thread.
            // Task.Run avoids blocking the UI thread.
            _scanTask = Task.Run(() => ScanLoopAsync(token), token);

            _logger("[Watchdog] Background scanner started.");
        }

        /// <summary>
        /// Stops the watchdog gracefully. Waits up to 5 seconds for
        /// the scan loop to acknowledge the cancellation.
        /// </summary>
        public async Task StopAsync()
        {
            if (_cts == null || _scanTask == null)
            {
                _logger("[Watchdog] Not running. Nothing to stop.");
                return;
            }

            _logger("[Watchdog] Stopping watchdog...");

            // Signal the cancellation token — the scan loop will
            // exit on the next Task.Delay check
            _cts.Cancel();

            try
            {
                // Wait for the loop to finish (with timeout)
                await _scanTask.WaitAsync(TimeSpan.FromSeconds(5));
            }
            catch (OperationCanceledException)
            {
                // Expected — Task.Delay throws when token is cancelled
            }
            catch (TimeoutException)
            {
                _logger("[Watchdog] WARNING: Scan loop did not stop within 5 seconds.");
            }

            _cts.Dispose();
            _cts = null;
            _scanTask = null;

            _logger($"[Watchdog] Stopped. Total processes killed this session: {_totalKilled}");
        }

        /// <summary>
        /// Synchronous stop method for use in cleanup handlers where
        /// async is not available (e.g., ProcessExit, Dispose).
        /// </summary>
        public void Stop()
        {
            if (_cts == null || _scanTask == null)
                return;

            _logger("[Watchdog] Stopping watchdog (sync)...");
            _cts.Cancel();

            try
            {
                // Block up to 3 seconds for graceful stop
                _scanTask.Wait(TimeSpan.FromSeconds(3));
            }
            catch (AggregateException)
            {
                // Expected — contains OperationCanceledException
            }

            _cts.Dispose();
            _cts = null;
            _scanTask = null;
        }

        /// <summary>
        /// Performs a single immediate scan and kill pass.
        /// Useful for an initial sweep before the background loop starts.
        /// </summary>
        public int ScanOnce()
        {
            _logger("[Watchdog] Performing single scan pass...");
            int killed = PerformScan();
            _logger($"[Watchdog] Single scan complete. Killed: {killed}");
            return killed;
        }

        // ════════════════════════════════════════════════════════════════
        // Core Scan Loop (Runs on Background Thread)
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// The main async scanning loop. Runs until cancellation is requested.
        ///
        /// CPU OPTIMIZATION:
        /// - Task.Delay suspends the thread (no busy-wait / spin-lock)
        /// - Process.GetProcesses() takes ~1-5ms on typical systems
        /// - With 2000ms interval, CPU duty cycle is ~0.1-0.25%
        /// - HashSet.Contains is O(1) — no linear search through blacklist
        ///
        /// CRASH RESILIENCE:
        /// The outer try-catch ensures the loop NEVER crashes entirely.
        /// Individual process errors are caught in PerformScan().
        /// Only CancellationToken can stop this loop.
        /// </summary>
        private async Task ScanLoopAsync(CancellationToken token)
        {
            _logger("[Watchdog] Scan loop entered on background thread.");

            // Perform an immediate first scan (don't wait 2 seconds)
            PerformScan();

            while (!token.IsCancellationRequested)
            {
                try
                {
                    // ── Sleep (CPU-efficient) ───────────────────────
                    // Task.Delay releases the thread back to the pool.
                    // The thread is NOT blocked — it's available for
                    // other work. The continuation fires after the delay.
                    await Task.Delay(ScanIntervalMs, token);

                    // ── Scan ────────────────────────────────────────
                    int killed = PerformScan();

                    // Reset failure counter on successful scan
                    _consecutiveFailures = 0;

                    if (killed > 0)
                    {
                        _logger($"[Watchdog] Scan complete. Killed {killed} process(es) this pass. " +
                                $"Total session kills: {_totalKilled}");
                    }
                }
                catch (OperationCanceledException)
                {
                    // Expected when StopAsync() cancels the token.
                    // Exit the loop gracefully.
                    break;
                }
                catch (Exception ex)
                {
                    // Unexpected error in the scan loop itself.
                    // Log it but NEVER let the loop die.
                    _consecutiveFailures++;
                    Debug.WriteLine($"[Watchdog] Scan loop error #{_consecutiveFailures}: {ex.Message}");

                    if (_consecutiveFailures >= MaxConsecutiveFailures)
                    {
                        _logger($"[Watchdog] WARNING: {_consecutiveFailures} consecutive scan failures. " +
                                "Watchdog is degraded but still running.");
                    }

                    // Wait before retrying to avoid tight error loops
                    try
                    {
                        await Task.Delay(ScanIntervalMs, token);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                }
            }

            _logger("[Watchdog] Scan loop exited.");
        }

        // ════════════════════════════════════════════════════════════════
        // Single Scan Pass
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Scans all running processes and kills any that match the blacklist.
        /// Returns the number of processes killed in this pass.
        ///
        /// ERROR HANDLING STRATEGY:
        /// Each process is inspected inside its own try-catch. This ensures
        /// that an Access Denied error on csrss.exe (for example) does not
        /// prevent us from scanning the remaining 200+ processes.
        ///
        /// Common exceptions:
        /// - Win32Exception: Access denied reading SYSTEM process properties
        /// - InvalidOperationException: Process exited between GetProcesses()
        ///   and our .ProcessName read (TOCTOU race condition)
        /// - ArgumentException: Process handle became invalid
        /// </summary>
        private int PerformScan()
        {
            int killedThisPass = 0;
            Process[] processes;

            try
            {
                processes = Process.GetProcesses();
            }
            catch (Exception ex)
            {
                // If we can't even enumerate processes, something is very wrong.
                // Log and return — the loop will retry on the next interval.
                Debug.WriteLine($"[Watchdog] Failed to enumerate processes: {ex.Message}");
                return 0;
            }

            foreach (var process in processes)
            {
                try
                {
                    // Skip our own process — never self-terminate
                    if (process.Id == _ownProcessId)
                        continue;

                    // Read the process name. This can throw Win32Exception
                    // for SYSTEM processes we don't have access to inspect.
                    string name = process.ProcessName;

                    // O(1) lookup in the HashSet blacklist
                    if (_blacklist.Contains(name))
                    {
                        _logger($"[Watchdog] ⚠ DETECTED blacklisted process: " +
                                $"{name} (PID: {process.Id}) — TERMINATING");

                        KillProcess(process, name);
                        killedThisPass++;
                        Interlocked.Increment(ref _totalKilled);
                    }
                }
                catch (Win32Exception)
                {
                    // Access denied — this is a SYSTEM/protected process.
                    // We can't read its name and don't need to — system
                    // processes are never on our blacklist.
                    // Silently skip. Do NOT log — this fires for ~20+
                    // processes per scan and would flood the log.
                }
                catch (InvalidOperationException)
                {
                    // Process exited between GetProcesses() and our read.
                    // Classic TOCTOU race — completely harmless. Skip.
                }
                catch (Exception)
                {
                    // Catch-all for any other unexpected per-process error.
                    // Skip this process and continue scanning the rest.
                }
                finally
                {
                    // Always dispose the Process object to release its handle.
                    // Failing to do this leaks kernel HANDLE objects.
                    process.Dispose();
                }
            }

            return killedThisPass;
        }

        /// <summary>
        /// Forcefully terminates a blacklisted process.
        /// Uses Process.Kill(entireProcessTree: true) to also kill
        /// child processes that the blacklisted app may have spawned.
        ///
        /// If Kill() fails (e.g., the process is protected or already
        /// exiting), we log the failure but don't crash.
        /// </summary>
        private void KillProcess(Process process, string name)
        {
            try
            {
                // Kill the entire process tree (parent + children).
                // This prevents tricks like AnyDesk spawning helper
                // processes that survive the parent kill.
                process.Kill(entireProcessTree: true);

                _logger($"[Watchdog] ✓ Killed: {name} (PID: {process.Id}) + child processes");
            }
            catch (Win32Exception ex)
            {
                // Access denied — process might be running as SYSTEM
                // or have higher privileges than us
                _logger($"[Watchdog] ✗ Cannot kill {name} (PID: {process.Id}): " +
                        $"Access Denied — {ex.Message}");

                // Fallback: try killing just the process (no tree)
                try
                {
                    process.Kill(entireProcessTree: false);
                    _logger($"[Watchdog] ✓ Killed {name} (PID: {process.Id}) without tree");
                }
                catch (Exception fallbackEx)
                {
                    _logger($"[Watchdog] ✗ Fallback kill also failed: {fallbackEx.Message}");
                }
            }
            catch (InvalidOperationException)
            {
                // Process already exited — our job is done
                _logger($"[Watchdog] {name} (PID: {process.Id}) already exited.");
            }
            catch (Exception ex)
            {
                _logger($"[Watchdog] ✗ Unexpected error killing {name}: {ex.Message}");
            }
        }

        // ════════════════════════════════════════════════════════════════
        // IDisposable
        // ════════════════════════════════════════════════════════════════

        public void Dispose()
        {
            if (!_disposed)
            {
                Stop();
                _disposed = true;
            }
        }
    }
}
