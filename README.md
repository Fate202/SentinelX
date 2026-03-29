# Projectt — Security Scanner Suite

A complete browser-based cybersecurity toolkit with two modules:

## 🔗 Module 1: Phishing Website Detector
Analyze any URL for phishing indicators using 15+ heuristic checks.

## 🦠 Module 2: File Malware Scanner
Scan any file locally in your browser for malware signatures, dangerous patterns, and threat indicators.

---

## File Structure

```
Projectt/
├── index.html              ← Phishing URL Detector
├── malware-scanner.html    ← File Malware Scanner
├── css/
│   ├── style.css           ← Shared styles & dark theme
│   └── malware.css         ← Malware scanner styles
├── js/
│   ├── detector.js         ← Phishing detection engine
│   ├── app.js              ← Phishing UI controller
│   ├── malware-detector.js ← Malware detection engine
│   └── malware-app.js      ← Malware scanner UI controller
└── README.md
```

---

## Malware Scanner Checks

- Dangerous file extensions (.exe, .bat, .vbs, .ps1, etc.)
- Double extension disguise (file.pdf.exe)
- Magic byte / file header analysis
- Entropy analysis (packed/encrypted payload detection)
- Suspicious code patterns (PowerShell, WScript, obfuscation)
- Known malware string signatures + EICAR test
- Office macro auto-execute detection
- Base64 payload detection
- Social engineering filename keywords
- Unicode direction override tricks
- IP-based C2 URL references
- Registry autorun persistence patterns

## How to Use

1. Extract the zip
2. Open `index.html` for phishing URL detection
3. Open `malware-scanner.html` for file malware scanning
4. All processing is local — files never leave your browser!

© 2025 Projectt Security Suite
