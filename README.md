# DRM Encrypt & View Desktop Application

A modern, secure, and elegant desktop application built with Python and Tkinter for encrypting PDF and image files with DRM protections and securely viewing them with expiry, device binding, and password authentication.

---
## 📦 Features

### Encryption Mode
- Select PDF or image files (.pdf, .jpg, .png)
- Set expiry date & time via integrated calendar & time picker
- Enter target MAC address or automatically use current device MAC
- Password protection (mandatory)
- AES-256 (CBC mode) encryption with embedded metadata header including expiry, MAC, file extension, and password
- Saves encrypted file as `.drm` extension
- Logs encryption details to CSV file (`log.csv`)

### View Mode
- Open `.drm` encrypted files
- Authenticate with password
- Automatic checks for expiry date and authorized MAC address
- If valid:
  - PDF viewer with page navigation and zoom (powered by PyMuPDF)
  - Image viewer supporting zoom and scroll
- Blocks unsupported file types safely
- Automatically cleans up decrypted temporary files after viewing
- Logs viewing attempts including denials to CSV log

### User Interface
- Clean light-themed UI with generous whitespace and readable typography
- Large elegant headlines and subdued neutral body text (#6b7280)
- Cards with soft rounded corners and subtle shadows for form areas
- Responsive full-width layout with centered max-width container for desktop
- Smooth transitions and clear visual hierarchy
- Scrollable forms for smaller screens or long content

---
## 🎨 Visual & UX Guidelines

This app is designed following **Default Design Guidelines** focused on minimal and elegant UI inspired by high-end component libraries:

- Light backgrounds (#ffffff) with ample breathing room
- Bold, large headings (48px+, weight 600–800)
- Neutral gray readable body text (16–18px)
- Cards with subtle rounded corners (~12px radius) and light shadows
- Large, clear buttons with soft hover effects
- Responsive layout with vertical stacking and consistent padding
- Accessible and semantic UI structure
- Smooth zoom and navigation interactions in viewers

---
## 🛠️ Technology Stack

- Python 3.7+
- Tkinter for GUI
- PyMuPDF (`fitz`) for rendering PDFs
- Pillow (`PIL`) for image handling
- tkcalendar for calendar widget
- PyCryptodome for AES-256 encryption
- CSV for simple logging

---
## 📦 Installation & Running Locally

1. Clone the repo:

   ```bash
   git clone https://github.com/yourusername/drm-encrypt-view.git
   cd drm-encrypt-view
