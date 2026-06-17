<div align="center">

  <!-- Agar logotipingiz bo‘lsa, shu yerga havolasini qo‘ying -->
  <img src="https://img.icons8.com/color/120/000000/security-checked.png" alt="SEB Logotipi">

  <h1>🛡️ Safe Exam Browser (SEB)</h1>
  <p><strong>Xavfsiz Onlayn Imtihonlar Uchun Korporativ Darajadagi Himoyalangan Brauzer</strong></p>

  <!-- Nishonlar -->
  <a href="https://github.com/Farruxjon-CODER/SafeExamBrowser-SEB-uz/releases"><img src="https://img.shields.io/github/v/release/Farruxjon-CODER/SafeExamBrowser-SEB-?color=blue&style=for-the-badge" alt="Reliz"></a>
  <a href="#"><img src="https://img.shields.io/badge/.NET-8.0-512BD4?style=for-the-badge&logo=dotnet" alt=".NET 8"></a>
  <a href="#"><img src="https://img.shields.io/badge/Platform-Windows%20x64-0078D6?style=for-the-badge&logo=windows" alt="Windows"></a>
  <a href="#"><img src="https://img.shields.io/badge/License-MIT-success?style=for-the-badge" alt="Litsenziya"></a>

</div>

<br>

## 📌 Umumiy Ma’lumot

**Safe Exam Browser (SEB)** — bu oddiy Windows kompyuterini onlayn imtihonlar, testlar va sertifikatlash jarayonlari uchun maxsus himoyalangan ish muhitiga aylantiruvchi yuqori xavfsizlikka ega dastur.

Dastur **C# WPF** texnologiyasida yaratilgan bo‘lib, **Windows API (Win32)** bilan chuqur integratsiyalashgan. SEB tizim yorliqlarini, oynalar o‘rtasida almashishni va ruxsatsiz dasturlarni bloklash orqali noqonuniy yordam olish urinishlarini bartaraf etadi hamda ta’lim muassasalari uchun maksimal darajada himoyalangan raqamli muhit yaratadi.

---

## 🚀 Asosiy Imkoniyatlar

* **🔒 Operatsion Tizim Darajasida Himoya:** `Windows`, `Alt+Tab`, `Ctrl+Esc` va `Alt+F4` kabi global tugmalar kombinatsiyalarini past darajadagi klaviatura nazorati orqali bloklaydi.
* **🚫 Task Manager Himoyasi:** Talabalar brauzerdan chiqib ketmasligi uchun Windows Registry orqali Task Manager'ni vaqtincha o‘chirib qo‘yadi.
* **🌐 Zamonaviy Veb Dvigatel:** **Microsoft Edge WebView2** asosida ishlaydi va zamonaviy onlayn imtihon platformalarini tez hamda mos ravishda yuklaydi.
* **💻 Kiosk Rejimi:** To‘liq ekran rejimini majburiy saqlaydi va oynani kichraytirish, o‘lchamini o‘zgartirish yoki chetlab o‘tishni oldini oladi.
* **📦 Bitta Faylli Dastur:** Barcha kerakli komponentlar ichiga joylashtirilgan yagona `.exe` fayl sifatida tarqatiladi va qo‘shimcha kutubxonalarni o‘rnatishni talab qilmaydi.

---

## 🏗️ Arxitektura va Texnologiyalar

* **Framework:** .NET 8.0 (WPF)
* **Dasturlash tili:** C#
* **Veb Dvigatel:** WebView2 (Chromium asosida)
* **Tizim Hooklari:** P/Invoke (Win32 API) orqali past darajadagi klaviatura nazorati (`WH_KEYBOARD_LL`)
* **O‘rnatuvchi:** Inno Setup Compiler (`Setup.exe` faylini avtomatik yaratadi)

---

## 🔐 Ikki Qatlamli Xavfsizlik Tizimi ("Pre-Boot" Tizimi)

Nazoratchilar uchun qulaylikni saqlagan holda yuqori xavfsizlikni ta’minlash maqsadida, SEB ikki bosqichli chiqish mexanizmidan foydalanadi:

### 1. Dinamik RAM Paroli (Sessiya Qatlami)

Dastur ishga tushirilganda nazoratchi bir martalik maxsus parol kiritadi. Ushbu parol faqat operativ xotirada (RAM) saqlanadi va dastur yopilganda avtomatik ravishda o‘chirib tashlanadi.

### 2. Super Administrator Zaxira Kaliti (Kriptografik Qatlam)

Agar sessiya paroli unutilsa, tizim oldindan yaratilgan **SHA-256 xeshlangan** asosiy kalitdan foydalanadi.

**Favqulodda yordam:**
Agar tizim bloklanib qolsa, vakolatli nazoratchilar kriptografik bypass kalitini olish uchun tizim arxitektori bilan Telegram orqali bog‘lanishlari mumkin:

**Telegram:** @xamidovc_dev

---

## 📥 O‘rnatish va Foydalanish

### O‘qituvchilar, Universitetlar va Test Markazlari uchun:

1. Relizlar sahifasiga o‘ting.
2. Eng so‘nggi `SafeExamBrowser_Setup_v1.0.exe` faylini yuklab oling.
3. O‘rnatuvchini ishga tushiring (Registry darajasidagi himoya uchun Administrator huquqlari talab qilinadi).
4. Ish stolida yaratilgan yorliq orqali dasturni oching.
5. Bir martalik sessiya parolini o‘rnating va imtihonni boshlang.

**Eslatma:** Imtihon tugagandan so‘ng dasturdan xavfsiz chiqish uchun `Ctrl + Shift + Q` tugmalarini bosing va sessiya parolingizni kiriting.

---

## 👨‍💻 Dasturchilar Uchun: Manba Koddan Yig‘ish

Loyihani kompyuteringizga yuklab olib kompilyatsiya qilish uchun:

```bash
# Repozitoriyani yuklab olish
git clone https://github.com/Farruxjon-CODER/SafeExamBrowser-SEB-.git

# Loyiha papkasiga o'tish
cd SafeExamBrowser-SEB-

# Loyihani tozalash va bitta fayl sifatida yig'ish
dotnet clean
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true
