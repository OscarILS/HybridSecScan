# ✅ Testing Checklist - HybridSecScan

## Pre-Testing Verification

- [x] Backend running on http://127.0.0.1:8000
- [x] Frontend running on http://localhost:5173
- [x] SQLite database initialized
- [x] Progress bars added to App.tsx
- [x] Vulnerable code samples created
- [x] Test URLs documented
- [x] Launch scripts available

---

## SAST Testing Checklist

### Setup Phase
- [ ] Open http://localhost:5173 in browser
- [ ] Navigate to SAST tab
- [ ] Verify file upload interface visible
- [ ] Verify tool selection dropdown shows Bandit and Semgrep

### Upload Phase
- [ ] Locate ProgramasPruebas/vulnerable_app.py
- [ ] Drag & drop or click to select file
- [ ] Click "Subir Archivo" button
- [ ] Wait for "Archivo subido correctamente" message
- [ ] Verify file path appears in input field

### Execution Phase
- [ ] Tool selected: Bandit
- [ ] Click "Ejecutar Auditoría" button
- [ ] ⭐ OBSERVE: Progress bar appears
  - [ ] Bar starts at 0%
  - [ ] Status shows "Analizando con BANDIT..."
  - [ ] Progress increases smoothly to ~90%
  - [ ] Final status: "✅ Análisis completado"
  - [ ] Bar reaches 100% (turns green)
  - [ ] Bar disappears after 2 seconds

### Results Phase
- [ ] JSON results appear in console area
- [ ] Results show vulnerability data
- [ ] Historial table updates with new entry
- [ ] No errors in browser console (F12)
- [ ] Backend logs show successful request

### Data Validation
- [ ] SAST type appears in historial
- [ ] Bandit tool name visible
- [ ] Timestamp recorded correctly
- [ ] Status shows "finished"
- [ ] File name visible in target column

---

## DAST Testing Checklist

### Setup Phase (Option A - Remote URL)
- [ ] Open http://localhost:5173 in browser
- [ ] Navigate to DAST tab
- [ ] Verify URL input field visible
- [ ] Copy URL: https://juice-shop.herokuapp.com/
- [ ] Paste into URL field
- [ ] Verify URL is accepted (no red border)

### Execution Phase
- [ ] Click "Ejecutar Auditoría" button
- [ ] ⭐ OBSERVE: Progress bar appears
  - [ ] Bar starts at 0%
  - [ ] Status shows "Ejecutando escaneo dinámico..."
  - [ ] Progress increases (slower than SAST - network dependent)
  - [ ] Can go up to 90% before waiting for response
  - [ ] Final status: "✅ Análisis completado"
  - [ ] Bar reaches 100% (turns green)

### Results Phase
- [ ] Results appear in console area
- [ ] DAST findings visible (if any)
- [ ] Historial updates with new entry
- [ ] No errors in browser console (F12)

### Data Validation
- [ ] DAST type appears in historial
- [ ] URL visible in target column (or truncated)
- [ ] Timestamp recorded
- [ ] Status shows "finished" or error if URL unavailable

---

## DAST Testing Checklist (Option B - Local App)

### App Installation Phase
- [ ] Open new PowerShell window
- [ ] Navigate to project root
- [ ] Run: `.\ProgramasPruebas\launch_vulnerable_apps.ps1`
- [ ] Select option 1 (OWASP Juice Shop)
- [ ] Wait for "VITE ready" or similar app startup message
- [ ] Note the URL (typically http://localhost:3000/)
- [ ] Verify app accessible by opening URL in browser

### HybridSecScan DAST Configuration
- [ ] Browser: http://localhost:5173 (different tab)
- [ ] Tab: DAST
- [ ] Enter URL: http://localhost:3000/
- [ ] Verify URL accepted

### Execution and Monitoring
- [ ] Click "Ejecutar Auditoría"
- [ ] ⭐ OBSERVE: Progress bar
  - [ ] Bar appears and starts animating
  - [ ] Status: "Ejecutando escaneo dinámico..."
  - [ ] Progress reaches near 100%
  - [ ] Scan completes and shows results
- [ ] Check results in console area
- [ ] Verify historial updated

### Cleanup
- [ ] Return to app terminal
- [ ] Press CTRL+C to stop app
- [ ] Confirm app has stopped
- [ ] Close terminal if desired

---

## Frontend UI Verification

### Navigation
- [ ] SAST/DAST tabs switchable
- [ ] Active tab highlighted
- [ ] Content changes when switching tabs
- [ ] Icons visible (Shield, Globe, Code)

### Form Elements
- [ ] File input works (click and drag)
- [ ] URL input accepts text
- [ ] Tool dropdown has options
- [ ] Buttons are clickable and change state

### Feedback Elements
- [ ] Upload message shows (green)
- [ ] Upload error shows (red) if applicable
- [ ] Scan error message shows if needed
- [ ] Progress bar renders correctly
  - [ ] Bar width matches percentage
  - [ ] Color transitions smoothly
  - [ ] Status text updates

### History/Results
- [ ] Historial table renders
- [ ] Columns have correct headers
- [ ] Rows populate after scan
- [ ] Data displays correctly
- [ ] Refresh button works

---

## Backend Integration Verification

### API Responses
- [ ] /health endpoint responds (200 OK)
- [ ] /upload/ endpoint accepts files
- [ ] /scan/sast endpoint processes requests
- [ ] /scan/dast endpoint accepts URLs
- [ ] /scan-results endpoint returns history

### Error Handling
- [ ] Invalid file type shows error
- [ ] File too large shows error
- [ ] Invalid URL shows error
- [ ] Missing required fields shows error
- [ ] Errors appear in both UI and terminal

### CORS
- [ ] No CORS errors in browser console
- [ ] Requests from 5173 → 8000 work
- [ ] Headers include proper CORS policy

---

## Performance Metrics

### SAST Scan
- [ ] Start time: __________
- [ ] End time: __________
- [ ] Total duration: __________
- [ ] Vulnerabilities found: __________
- [ ] File size analyzed: __________

### DAST Scan
- [ ] Start time: __________
- [ ] End time: __________
- [ ] Total duration: __________
- [ ] Issues found: __________
- [ ] Target URL: __________

---

## Documentation & Evidence

- [ ] Screenshot of progress bar at 50% (SAST)
- [ ] Screenshot of progress bar at 50% (DAST)
- [ ] Screenshot of completed results (SAST)
- [ ] Screenshot of completed results (DAST)
- [ ] Screenshot of historial table
- [ ] Console output screenshot (backend logs)
- [ ] Browser DevTools screenshot (no errors)

---

## Browser DevTools Check

### Console Tab
- [ ] No red errors
- [ ] No network errors (all 200 OK)
- [ ] Only normal React warnings if any

### Network Tab
- [ ] POST /upload/ - 200 OK
- [ ] POST /scan/sast - 200 OK
- [ ] POST /scan/dast - 200 OK
- [ ] GET /scan-results - 200 OK
- [ ] All responses have proper JSON

### Performance Tab
- [ ] Page load < 2 seconds
- [ ] Scan submission < 1 second
- [ ] Results rendering smooth

---

## Edge Cases & Error Testing

- [ ] Upload non-code file (.txt) → error shown
- [ ] Upload empty file → error shown
- [ ] Enter invalid URL → error shown
- [ ] Click scan without file (SAST) → error shown
- [ ] Click scan without URL (DAST) → error shown
- [ ] Stop analysis mid-way → graceful handling
- [ ] Refresh page during scan → state preserved?

---

## Final Sign-Off

**Tester Name:** ____________________  
**Date:** ____________________  
**Time:** ____________________  

**Overall Status:**
- [ ] ✅ ALL TESTS PASSED
- [ ] ⚠️ SOME ISSUES (List below)
- [ ] ❌ CRITICAL FAILURES

**Issues Found:**
1. ________________________________________
2. ________________________________________
3. ________________________________________

**Notes & Observations:**
_________________________________________
_________________________________________
_________________________________________

**Recommendation:**
- [ ] Ready for production
- [ ] Ready with minor fixes
- [ ] Needs significant rework
- [ ] Hold for further testing

---

## For Thesis Documentation

Use the results from this checklist to document:

**Chapter 4 - Results & Validation:**
- Screenshot of SAST progress bar
- Screenshot of DAST progress bar
- Performance metrics (timing)
- Number of vulnerabilities detected
- Comparison with manual analysis
- System accuracy measurements

**Chapter 5 - Conclusions:**
- Effectiveness of progress indicators
- User experience during scanning
- Reliability of detection
- Recommendations for improvement

---

**Last Updated:** November 27, 2025  
**Status:** Ready for Testing ✅
