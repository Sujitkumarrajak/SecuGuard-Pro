# 🛡️ SecuGuard-Pro

SecuGuard-Pro is a secure file upload scanning system powered by Flask, JWT Authentication, VirusTotal API integration, PDF report generation, and rate limiting. It allows users to upload files, scan them for malware or threats, and receive detailed scan results in downloadable PDF format.

---

## 🚀 Features

- 🔒 **JWT Authentication** (Register/Login)
- 🛡️ **VirusTotal File Scan Integration**
- 📑 **PDF Report Generation**
- ⏱️ **Rate Limiting (5 requests/minute)**
- 🌐 **RESTful API with Secure Endpoints**
- 📦 **Modular Flask App Structure**
- ✅ **Postman Tested**
- ⚙️ **CI/CD Setup with GitHub Actions (Optional)**

---

## 🧠 Tech Stack

- **Backend:** Flask, Flask-JWT-Extended, Flask-Limiter
- **API Integration:** VirusTotal API (`/files` endpoint)
- **PDF Reports:** `fpdf`
- **Security:** JWT, Rate Limiting, File Type Validation
- **DevOps:** GitHub Actions (CI/CD), .env config

---

## 📂 Folder Structure

SecuGuard-Pro/
│
├── app/
│ ├── init.py
│ ├── routes/
│ │ ├── auth.py
│ │ └── scan.py
│ └── utils.py
│
├── reports/ # PDF reports saved here
├── .env.example # Replace with your real .env
├── requirements.txt
├── run.py
└── README.md


