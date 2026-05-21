<div align="center">
  
  <!-- Agar logotipingiz bo'lsa, shu yerga linkini qo'yasiz -->
  <img src="https://www.flaticon.com/free-icon/cyber-security_5964156" alt="SEB Logo">

  <h1>🛡️ Safe Exam Browser (SEB)</h1>
  <p><strong>Enterprise-Grade Lockdown Browser for Secure Online Assessments</strong></p>

  <!-- Badges (Nishonlar) -->
  <a href="https://github.com/Farruxjon-CODER/SafeExamBrowser-SEB-/releases"><img src="https://img.shields.io/github/v/release/Farruxjon-CODER/SafeExamBrowser-SEB-?color=blue&style=for-the-badge" alt="Release"></a>
  <a href="#"><img src="https://img.shields.io/badge/.NET-8.0-512BD4?style=for-the-badge&logo=dotnet" alt=".NET 8"></a>
  <a href="#"><img src="https://img.shields.io/badge/Platform-Windows%20x64-0078D6?style=for-the-badge&logo=windows" alt="Windows"></a>
  <a href="#"><img src="https://img.shields.io/badge/License-MIT-success?style=for-the-badge" alt="License"></a>

</div>

<br>

## 📌 Overview

**Safe Exam Browser (SEB)** is a highly secure desktop application designed to transform any standard Windows computer into a secure workstation for conducting online exams, assessments, and certifications. 

Built with **C# WPF** and integrating deeply with the **Windows API (Win32)**, SEB completely neutralizes cheating attempts by blocking system shortcuts, task switching, and unauthorized applications, providing institutions with a 100% cheat-proof digital environment.

---

## 🚀 Key Features

*   **🔒 OS-Level Lockdown:** Intercepts and blocks global hotkeys including `Windows Key`, `Alt+Tab`, `Ctrl+Esc`, and `Alt+F4` using low-level keyboard hooks.
*   **🚫 Task Manager Neutralization:** Prevents students from bypassing the browser by dynamically disabling Task Manager via Windows Registry.
*   **🌐 Modern Rendering Engine:** Powered by **Microsoft Edge WebView2**, ensuring lightning-fast and compatible rendering of modern web-based exam portals.
*   **💻 Kiosk Mode:** Enforces a persistent Full-Screen overlay that cannot be minimized, resized, or bypassed.
*   **📦 Single-File Deployment:** Fully self-contained `.exe` compiled with embedded native C++ DLLs for seamless execution without requiring local dependencies.

---

## 🏗️ Architecture & Tech Stack

*   **Framework:** .NET 8.0 (WPF)
*   **Language:** C#
*   **Web Engine:** WebView2 (Chromium-based)
*   **System Hooks:** P/Invoke (Win32 API) for Low-Level Keyboard Hooks (`WH_KEYBOARD_LL`).
*   **Installer:** Inno Setup Compiler (Generates automated `Setup.exe`).

---

## 🔐 Dual-Layer Security Model (The "Pre-Boot" System)

To ensure operational flexibility for invigilators without compromising security, SEB implements a sophisticated dual-layer exit strategy:

1.  **Dynamic RAM Password (Session Layer):** Upon launch, the invigilator enters a custom one-time password. This password is kept strictly in volatile memory (RAM) and is securely wiped upon exit.
2.  **Super-Admin Fallback (Cryptographic Layer):** If the session password is forgotten, the system falls back to a hardcoded **SHA-256 Hashed** master key. 
    *   *Test the fallback:* Press `Ctrl + Shift + Q` to exit and enter the Super-Admin phrase: `SuperAdmin-999`.

---

## 📥 Installation & Usage

For Teachers, Universities, and Test Centers:

1.  Navigate to the [Releases Page](https://github.com/Farruxjon-CODER/SafeExamBrowser-SEB-/releases).
2.  Download the latest `SafeExamBrowser_Setup_v1.0.exe`.
3.  Run the installer (requires Administrator privileges for registry-level security).
4.  Launch the app from the Desktop Shortcut.
5.  Set your one-time session password and start the exam!

*(To exit the application gracefully after an exam, press `Ctrl + Shift + Q` and enter your session password).*

---

## 👨‍💻 For Developers: Building from Source

To clone and compile this project locally:

```bash
# Clone the repository
git clone [https://github.com/Farruxjon-CODER/SafeExamBrowser-SEB-.git](https://github.com/Farruxjon-CODER/SafeExamBrowser-SEB-.git)

# Navigate to the project directory
cd SafeExamBrowser-SEB-

# Clean and Publish as a Single File
dotnet clean
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true
