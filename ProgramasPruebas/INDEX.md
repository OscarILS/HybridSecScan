![HybridSecScan Testing Suite](https://img.shields.io/badge/HybridSecScan-Testing%20Suite-blue)
![Status](https://img.shields.io/badge/Status-Ready%20for%20Testing-brightgreen)
![Updated](https://img.shields.io/badge/Updated-Nov%2027%202025-informational)

# 🔐 ProgramasPruebas - Complete Testing Suite

Complete testing environment for HybridSecScan with vulnerable applications, progress bars, and comprehensive documentation.

## 📦 What's Included

### 🚨 Vulnerable Code Samples
- **vulnerable_app.py** - Flask application with 9 SAST vulnerabilities
- **vulnerable_js.js** - JavaScript code with 12 SAST vulnerabilities  
- **vulnerable_sql.sql** - SQL scripts with 10 best practice violations

### 📊 Progress Bars (Frontend Enhancement)
- ✅ Added to App.tsx for both SAST and DAST
- ✅ Smooth animation from 0-100%
- ✅ Dynamic status messages
- ✅ Color transition (primary → green)
- ✅ Auto-hide after completion

### 📚 Documentation
| File | Purpose | Audience |
|------|---------|----------|
| **GUIA_PRUEBAS.md** | Complete testing guide with screenshots | Developers |
| **TESTING_CHECKLIST.md** | Step-by-step verification checklist | QA / Testers |
| **QUICK_REFERENCE.sh** | Quick command reference | All users |
| **README.md** | Quick start & overview | New users |
| **test_urls.txt** | Curated list of test URLs | DAST testing |

### 🛠️ Launcher Scripts
- **launch_vulnerable_apps.ps1** - PowerShell with interactive menu
- **launch_vulnerable_apps.bat** - Windows CMD launcher

---

## 🚀 Quick Start

### 1️⃣ **SAST Testing (2 minutes)**

```
1. Open: http://localhost:5173
2. Tab: SAST
3. Upload: ProgramasPruebas/vulnerable_app.py
4. Tool: Bandit
5. Execute: "Ejecutar Auditoría"
   → Watch Progress Bar: 0% → 100% ✅
6. Results: 16 vulnerabilities found
```

**Expected Progress Bar:**
```
📊 Análisis SAST          Analizando con BANDIT...
████████████░░░░░░░░░░░ 45%
```

### 2️⃣ **DAST Testing - Remote URL (5 minutes)**

```
1. Open: http://localhost:5173
2. Tab: DAST
3. Enter URL: https://juice-shop.herokuapp.com/
4. Execute: "Ejecutar Auditoría"
   → Watch Progress Bar: 0% → 100% ✅
5. Results: OWASP ZAP findings
```

**Expected Progress Bar:**
```
🌐 Análisis DAST         Ejecutando escaneo dinámico...
██████████████░░░░░░░░░ 65%
```

### 3️⃣ **DAST Testing - Local App (15 minutes)**

```powershell
# Terminal 1: Start vulnerable app
.\ProgramasPruebas\launch_vulnerable_apps.ps1
# Select option 1 (Juice Shop)
# Wait for http://localhost:3000/

# Terminal 2: HybridSecScan (already running)
# Tab: DAST
# URL: http://localhost:3000/
# Execute and observe progress bar
```

---

## 📊 Progress Bar Features

### SAST Progress
- **Initial:** "Iniciando..."
- **Running:** "Analizando con BANDIT..." or "Analizando con SEMGREP..."
- **Complete:** "✅ Análisis completado" (Green, 100%)
- **Auto-hide:** After 2 seconds

### DAST Progress
- **Initial:** "Iniciando..."
- **Running:** "Ejecutando escaneo dinámico..."
- **Complete:** "✅ Análisis completado" (Green, 100%)
- **Auto-hide:** After 2 seconds

### Visual Characteristics
- 🎨 Smooth CSS transitions (0.3s)
- 📈 Realistic progress simulation
- 🎯 Responsive design
- ♿ Accessible indicators
- 📱 Mobile-friendly

---

## 📁 File Structure

```
ProgramasPruebas/
├── CODE SAMPLES
│   ├── vulnerable_app.py          (Python/Flask - 9 vulns)
│   ├── vulnerable_js.js           (JavaScript - 12 vulns)
│   └── vulnerable_sql.sql         (SQL - 10 vulns)
│
├── DOCUMENTATION
│   ├── README.md                  (This file)
│   ├── GUIA_PRUEBAS.md            (Complete guide - Spanish)
│   ├── TESTING_CHECKLIST.md       (Verification steps)
│   ├── QUICK_REFERENCE.sh         (Commands reference)
│   └── test_urls.txt              (Test URLs collection)
│
└── LAUNCHERS
    ├── launch_vulnerable_apps.ps1 (PowerShell - Recommended)
    └── launch_vulnerable_apps.bat (CMD - Basic)
```

---

## 🔗 URLs for DAST Testing

### Local (After Installation)
| App | URL | Time to Setup |
|-----|-----|----------------|
| OWASP Juice Shop | http://localhost:3000/ | 5-10 min |
| NodeGoat | http://localhost:4000/ | 10-15 min |
| DVWA | http://localhost/DVWA/ | 5 min (Docker) |
| WebGoat | http://localhost:8080/WebGoat/ | 5 min (Docker) |

### Remote (No Installation)
| App | URL | Pros |
|-----|-----|------|
| Juice Shop | https://juice-shop.herokuapp.com/ | Always available |
| WebGoat | https://webgoat.herokuapp.com/WebGoat/ | Well-maintained |
| PHP Vuln | http://testphp.vulnweb.com/ | Good for SQL injection testing |

---

## ✨ Vulnerabilities Documented

### Python/Flask (9 Total)
1. Hardcoded secrets
2. SQL Injection
3. Command Injection
4. Insecure deserialization
5. Path Traversal
6. Insecure temporary files
7. Use of assert for validation
8. Insecure random for security
9. Debug mode enabled in production

### JavaScript (12 Total)
1. eval() in user input
2. XSS via innerHTML
3. Hardcoded credentials
4. Math.random() for tokens
5. JSON.parse without validation
6. SSRF via fetch
7. Function constructor abuse
8. External scripts without CSP
9. localStorage for auth tokens
10. Unencrypted password transmission
11. ReDoS regular expressions
12. Sensitive data in comments

### SQL (10 Total)
1. Excessive user privileges
2. Weak passwords
3. Sensitive data in comments
4. SQL Injection vulnerability
5. Unencrypted sensitive data
6. Missing critical indices
7. Overly open permissions
8. Missing transactions
9. Unsafe triggers
10. Unencrypted sessions

---

## 🎯 Testing Workflow

```
┌─────────────────┐
│  START TESTING  │
└────────┬────────┘
         │
    ┌────▼─────────┬──────────────┐
    │              │              │
    ▼              ▼              ▼
┌─────────┐  ┌─────────┐  ┌──────────┐
│ SAST    │  │ DAST    │  │ DAST     │
│ Local   │  │ Remote  │  │ Local    │
│ (2 min) │  │ (5 min) │  │ (15 min) │
└────┬────┘  └────┬────┘  └─────┬────┘
     │            │             │
     │    Watch   │    Watch    │
     │   Progress │   Progress  │
     │    Bars! 📊│    Bars! 🌐 │
     │            │             │
     └────┬───────┴─────────┬───┘
          │                 │
          ▼                 ▼
      ┌─────────────────────────────┐
      │   CAPTURE RESULTS FOR       │
      │      THESIS CHAPTER 4       │
      └─────────────────────────────┘
```

---

## 📈 Expected Results

### SAST Scan (vulnerable_app.py with Bandit)
```json
{
  "scan_type": "SAST",
  "tool": "bandit",
  "vulnerabilities_found": 16,
  "severity": {
    "CRITICAL": 0,
    "HIGH": 0,
    "MEDIUM": 5,
    "LOW": 11
  },
  "execution_time": "~2 seconds",
  "progress_bar": "✅ Visible and animated"
}
```

### DAST Scan (juice-shop.herokuapp.com)
```json
{
  "scan_type": "DAST",
  "tool": "OWASP ZAP",
  "issues_found": "Multiple",
  "categories": [
    "XSS Vulnerabilities",
    "SQL Injection",
    "CORS Misconfigurations",
    "Authentication Issues"
  ],
  "execution_time": "~30-60 seconds",
  "progress_bar": "✅ Visible and animated"
}
```

---

## ⚙️ Requirements

| Component | Version | Purpose |
|-----------|---------|---------|
| Python | 3.7+ | SAST analysis |
| Node.js | 14+ | JavaScript tools |
| npm | 6+ | Package management |
| Docker | Latest | Container apps |
| Git | Latest | Repository cloning |
| FastAPI | 0.100+ | Backend (already installed) |
| React | 18+ | Frontend (already installed) |

---

## 🔍 Verification Checklist

- [x] 3 vulnerable code samples created
- [x] Progress bars integrated in App.tsx
- [x] SAST progress shows 0-100%
- [x] DAST progress shows 0-100%
- [x] Status messages dynamic
- [x] Colors transition smoothly
- [x] Progress bar auto-hides
- [x] 5 documentation files created
- [x] 2 launcher scripts ready
- [x] Test URLs documented
- [x] Backend running ✅
- [x] Frontend running ✅
- [x] Database initialized ✅

---

## 📝 For Thesis Documentation

### Chapter 4 - Results & Validation

Use these resources to document:

1. **Experimental Setup**
   - Screenshots of HybridSecScan UI
   - Progress bar screenshots at different stages
   - Test applications and their vulnerabilities

2. **Execution Results**
   - SAST scan results with metrics
   - DAST scan results with findings
   - ML correlation outputs
   - Timing and performance data

3. **Progress Indicators**
   - Evidence of progress bar functionality
   - User experience improvements
   - Real-time feedback mechanisms

4. **Validation**
   - Accuracy of vulnerability detection
   - Comparison with manual analysis
   - ML model performance metrics
   - Cross-correlation effectiveness

5. **Conclusions**
   - System reliability assessment
   - Practical effectiveness
   - Recommendations for improvement
   - Future enhancements

---

## 🚨 Important Notes

⚠️ **Security Notice:**
- These applications have intentional vulnerabilities
- Use only in controlled environments (localhost)
- Never deploy vulnerable code to production
- Do not run scans on external systems without authorization

✅ **Best Practices:**
- Always test on local machines first
- Use headless mode for batch testing
- Document all findings
- Validate results against known baselines
- Monitor system resources during DAST

---

## 📞 Support Resources

- **HybridSecScan Docs:** `../README.md`
- **Backend API:** http://localhost:8000/docs
- **Frontend UI:** http://localhost:5173
- **Testing Guide:** `./GUIA_PRUEBAS.md`
- **Bandit Docs:** https://bandit.readthedocs.io/
- **OWASP:** https://owasp.org/

---

## 📅 Maintenance

| Item | Last Updated | Status |
|------|--------------|--------|
| Vulnerable apps | Nov 27, 2025 | ✅ Current |
| Progress bars | Nov 27, 2025 | ✅ Implemented |
| Documentation | Nov 27, 2025 | ✅ Complete |
| Scripts | Nov 27, 2025 | ✅ Tested |
| URLs | Nov 27, 2025 | ✅ Verified |

---

## 🎓 Final Notes

This testing suite is designed for:
- ✅ Undergraduate thesis validation
- ✅ Security research
- ✅ Tool evaluation
- ✅ Educational purposes
- ✅ Proof-of-concept demonstrations

**Status:** Ready for production testing ✅  
**Last Updated:** November 27, 2025  
**Maintainer:** HybridSecScan Project
