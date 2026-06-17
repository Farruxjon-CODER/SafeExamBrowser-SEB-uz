// ============================================================================
// SafeExamBrowser — App.xaml.cs (Application Entry Point)
//
// STARTUP FLOW:
//   1. Application starts → WPF loads SetupWindow.xaml (via StartupUri).
//   2. SetupWindow collects the teacher's session password.
//   3. SetupWindow stores the password in SessionManager, then opens
//      MainWindow and closes itself.
//   4. MainWindow activates all lockdown stages (1-4).
//
// SHUTDOWN BEHAVIOR:
//   - ShutdownMode = OnLastWindowClose (default). When MainWindow closes
//     (after authorized exit), the application terminates.
//
// GLOBAL CRASH LOGGING:
//   - Subscribes to DispatcherUnhandledException (WPF UI thread crashes)
//     and AppDomain.CurrentDomain.UnhandledException (CLR-level crashes).
//   - On ANY unhandled exception, the full Exception.ToString() (message +
//     stack trace) is written to Desktop\SEB_CrashLog.txt.
//   - A MessageBox is shown so the crash is NEVER silent.
// ============================================================================

using System;
using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace SafeExamBrowser;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : Application
{
    // ════════════════════════════════════════════════════════════════
    // Crash Log Configuration
    // ════════════════════════════════════════════════════════════════

    /// <summary>
    /// Full path to the crash log file on the user's Desktop.
    /// </summary>
    private static readonly string CrashLogPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
        "SEB_CrashLog.txt"
    );

    // ════════════════════════════════════════════════════════════════
    // Application Startup — Wire Global Exception Handlers
    // ════════════════════════════════════════════════════════════════

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // ── Handler 1: WPF Dispatcher (UI thread) exceptions ────────
        // These are exceptions thrown on the WPF UI thread that bubble
        // up past all try-catch blocks. Without this handler, the app
        // would crash silently or show a generic Windows error dialog.
        DispatcherUnhandledException += OnDispatcherUnhandledException;

        // ── Handler 2: CLR-level exceptions (all threads) ───────────
        // Catches exceptions on background threads, Task continuations,
        // and finalizer threads. This is the last-resort safety net.
        AppDomain.CurrentDomain.UnhandledException += OnAppDomainUnhandledException;
    }

    // ════════════════════════════════════════════════════════════════
    // Exception Handlers
    // ════════════════════════════════════════════════════════════════

    /// <summary>
    /// Handles unhandled exceptions on the WPF Dispatcher (UI) thread.
    /// Logs the crash, notifies the user, and shuts down gracefully.
    /// </summary>
    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        // Mark as handled to prevent the default Windows crash dialog
        e.Handled = true;

        WriteCrashLog("DispatcherUnhandledException", e.Exception);
        ShowCrashMessage();

        // Shut down gracefully — teardown handlers in MainWindow will fire
        Shutdown(1);
    }

    /// <summary>
    /// Handles unhandled exceptions at the CLR/AppDomain level.
    /// These typically come from background threads and are always fatal.
    /// </summary>
    private void OnAppDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        var exception = e.ExceptionObject as Exception;
        WriteCrashLog("AppDomain.UnhandledException", exception);
        ShowCrashMessage();

        // AppDomain unhandled exceptions are fatal by default;
        // the CLR will terminate the process after this handler returns.
    }

    // ════════════════════════════════════════════════════════════════
    // Crash Log Writer
    // ════════════════════════════════════════════════════════════════

    /// <summary>
    /// Writes the full exception details to Desktop\SEB_CrashLog.txt.
    /// Appends to the file so multiple crashes in one session are captured.
    /// Uses a try-catch internally — if even logging fails, we still
    /// show the MessageBox.
    /// </summary>
    private static void WriteCrashLog(string source, Exception? exception)
    {
        try
        {
            string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
            string separator = new string('═', 72);

            string logEntry =
                $"{separator}{Environment.NewLine}" +
                $"XAVFSIZ IMTIHON BRAUZERI — NOSOZLIK HISOBOTI{Environment.NewLine}" +
                $"Vaqt       : {timestamp}{Environment.NewLine}" +
                $"Manba     : {source}{Environment.NewLine}" +
                $"Tugatilmoqda: {(source.Contains("AppDomain") ? "Ha (muhim)" : "Yo'q (qayta ishlangan)")}{Environment.NewLine}" +
                $"{separator}{Environment.NewLine}" +
                $"{(exception?.ToString() ?? "Xatolik tafsilotlari mavjud emas.")}{Environment.NewLine}" +
                $"{separator}{Environment.NewLine}{Environment.NewLine}";

            File.AppendAllText(CrashLogPath, logEntry);
        }
        catch
        {
            // Last resort: if we can't even write the log file, there's
            // nothing more we can do. The MessageBox below will still fire.
        }
    }

    /// <summary>
    /// Shows a simple MessageBox informing the user that a crash occurred
    /// and where to find the log file.
    /// </summary>
    private static void ShowCrashMessage()
    {
        try
        {
            MessageBox.Show(
                "Muhim xatolik yuz berdi va Xavfsiz imtihon brauzeri yopilishi kerak.\n\n" +
                $"Nosozlik hisoboti quyidagi manzilga saqlandi:\n{CrashLogPath}\n\n" +
                "Iltimos, ushbu faylni IT administratoringizga yuboring.",
                "Xavfsiz imtihon brauzeri — Muhim xatolik",
                MessageBoxButton.OK,
                MessageBoxImage.Error
            );
        }
        catch
        {
            // If even the MessageBox fails (e.g., no UI thread available),
            // there's nothing more we can do. The log file is our last hope.
        }
    }
}
