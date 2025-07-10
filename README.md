# BrowserTriage

A comprehensive browser forensics and security analysis tool for incident response and security research. BrowserTriage extracts browser artifacts (history, cookies, downloads) from multiple browsers and platforms, performs threat detection analysis, and provides URL reputation checking to identify potential security incidents.

## 🎯 Purpose

BrowserTriage was developed to assist security analysts and incident responders in quickly analyzing browser artifacts during security investigations. It bridges the gap between full disk imaging and rapid triage by providing focused browser artifact extraction with built-in threat detection capabilities.

## ✨ Features

### Browser Support
- **Chrome/Chromium** - History, cookies, downloads with referrer tracking
- **Mozilla Firefox** - Multi-profile support, history, cookies, downloads  
- **Microsoft Edge** - Chromium-based Edge artifact extraction

### Platform Support
- **Windows** - Local and remote extraction via WinRM/WMI/PSEXEC
- **Linux** - Local and remote extraction via SSH
- **Cross-platform** - Automatic OS detection for remote systems

### Security Analysis
- **URL Reputation Checking**
  - VirusTotal API integration (free tier support)
  - URLhaus malware feed analysis
  - Local Master Block List (MBL) checking
- **Threat Detection Engine**
  - Cross-Site Scripting (XSS) pattern detection
  - SQL Injection (SQLi) pattern matching
  - Cross-Site Request Forgery (CSRF) indicators
  - Phishing domain detection (typosquatting, suspicious patterns)
  - Malware download indicators
  - Command & Control (C2) communication patterns
  - Social engineering tactics identification

### Advanced Capabilities
- **Remote Extraction** - Extract from remote systems without installing Python
- **Multi-User Support** - Process all users or specific target users
- **URL Encoding Detection** - Handles multiple encoding variants for evasion detection
- **Rate Limiting** - Respects API rate limits (VirusTotal free tier: 4 requests/minute)
- **Flexible Output** - CSV and JSON formats with threat correlation

## 🚀 Installation

### Prerequisites

```bash
# Required Python packages
pip install sqlite3 pathlib datetime logging argparse csv paramiko

# Optional packages for enhanced functionality
pip install pypsrp          # For Windows WinRM remote execution
pip install wmi             # For Windows WMI remote execution (Windows only)
pip install vt-py           # For VirusTotal API integration
pip install requests        # For URLhaus feed downloads
```

### Quick Setup

1. **Clone or download the tool**
```bash
git clone <repository_url>
cd browsertriage
```

2. **Verify installation**
```bash
python browsertriage.py --help
```

3. **Check available browsers**
```bash
python browsertriage.py -lb
```

## 📖 Usage

### Basic Local Extraction

```bash
# Extract all artifacts from all browsers for current user
python browsertriage.py -u $USER -b all

# Extract from specific browser and user
python browsertriage.py -u alice -b chrome

# Extract from all users (requires appropriate permissions)
python browsertriage.py -u all -b all
```

### Remote Extraction

```bash
# Remote Windows system
python browsertriage.py -r 192.168.1.100 -rU administrator -u bob -b all

# Remote Linux system  
python browsertriage.py -r 192.168.1.50 -rU admin -u alice -b firefox

# Extract from all users on remote system
python browsertriage.py -r 192.168.1.100 -rU administrator -u all -b all
```

### Security Analysis Options

```bash
# Enable all threat detection categories
python browsertriage.py -u alice -b all --detect-all

# Enable specific detection categories
python browsertriage.py -u alice -b chrome --detect-web-attacks
python browsertriage.py -u alice -b all --detect-malware --detect-phishing

# URL reputation checking with VirusTotal
python browsertriage.py -u alice -b all -vt

# URL reputation with URLhaus feeds (no API key required)
python browsertriage.py -u alice -b all -uh

# All reputation services
python browsertriage.py -u alice -b all -ar

# Local Master Block List checking
python browsertriage.py -u alice -b all -m /path/to/blocklist.csv
```

### Output Control

```bash
# Specify output directory
python browsertriage.py -u alice -b all -o /tmp/analysis

# Generate summary report
python browsertriage.py -u alice -b all -s

# JSON output format
python browsertriage.py -u alice -b all --format json

# Split artifacts into separate files
python browsertriage.py -u alice -b all --split-artifacts
```

### Comprehensive Analysis Example

```bash
# Full analysis with all detection and reputation services
python browsertriage.py \
  -u all \
  -b all \
  --detect-all \
  -ar \
  -s \
  --format csv \
  -o ./investigation_results
```

## ⚙️ Configuration

### VirusTotal API Setup

1. Obtain a free API key from [VirusTotal](https://www.virustotal.com/gui/join-us)
2. The tool will prompt for the API key when using `-vt` or `-ar` options
3. **Rate Limits**: Free tier allows 4 requests per minute (15-second intervals)

### URLhaus Configuration

URLhaus feeds are downloaded automatically when using `-uh` or `-ar` options:
- **Feed URL**: https://urlhaus.abuse.ch/downloads/text/
- **Update Frequency**: Every 24 hours
- **Storage**: `./urlhaus_data/` directory

### Local Master Block List (MBL)

Supports CSV and plain text formats:
```csv
# CSV format (first column used)
malicious-site.com,description
evil.example.org,phishing site

# Plain text format (one entry per line)
malicious-site.com
evil.example.org
```

## 📊 Output Files

### Generated Reports

| File | Description | Content |
|------|-------------|---------|
| `browser_artifacts_[user]_[timestamp].csv` | Main artifact file | All browser data with threat annotations |
| `browser_summary_[timestamp].csv` | Summary report | Consolidated view across all users/browsers |
| `threat_report_[timestamp].csv` | Security alerts | URLs flagged as malicious/suspicious |
| `detailed_threat_report_[timestamp].csv` | Detailed threats | Full threat detection analysis |

### Key Data Fields

**History Entries:**
- URL, title, visit time, visit count, referrer URL
- Reputation risk level, malicious/suspicious flags
- Threat detection results (XSS, SQLi, phishing, etc.)
- Evidence and mitigation recommendations

**Download Entries:**
- Filename, source URL, download time, file size, state
- Malware detection indicators
- Source reputation analysis

**Cookie Entries:**
- Host, name, value, creation/expiry times
- Security flags (secure, httponly, samesite)

## 🔒 Security Considerations

### Threat Detection Limitations

The threat detection engine uses pattern-based analysis and may produce:
- **False Positives**: Legitimate URLs flagged as threats
- **False Negatives**: Actual threats not detected
- **Encoding Evasion**: Sophisticated encoding may bypass detection

**Recommendation**: Always correlate findings with other security tools and manual analysis.

### Remote Execution Security

- **Credentials**: Tool requires administrative credentials for remote systems
- **Network Traffic**: Uses encrypted channels (WinRM/SSH) but avoid over untrusted networks
- **Temporary Files**: Creates temporary files on target systems (automatically cleaned up)

### Privacy Considerations

- **Browser Data**: Contains sensitive user browsing information
- **Output Security**: Secure generated reports appropriately
- **API Keys**: Protect VirusTotal API keys and respect rate limits

## 🔧 Technical Details

### Architecture

```
browsertriage/
├── browsertriage.py           # Main application entry point
├── nix_browsers.py           # Linux browser extraction
├── win_browsers.py           # Windows browser extraction  
├── attack_detection.py       # Threat detection engine
├── remote/                   # Remote execution framework
│   ├── remote_manager.py     # Platform detection and delegation
│   ├── windows_remote.py     # Windows remote execution
│   └── linux_remote.py      # Linux remote execution
└── reputation/               # URL reputation services
    ├── reputation_manager.py # Service coordination
    ├── api_reputation.py     # VirusTotal API client
    └── local_reputation.py   # Local feed processing
```

### Database Handling

- **SQLite Processing**: Uses Python sqlite3 for browser database access
- **Locked Files**: Handles locked browser databases using:
  - SQLite backup API for read-only access
  - ROBOCOPY with backup mode on Windows
  - File copying with process termination
- **Multi-Profile**: Firefox profiles.ini parsing for multi-profile support

### Detection Engine

**URL Encoding Support:**
- Standard percent encoding (`%20`, `%3C`, etc.)
- Plus encoding (`+` to space conversion)
- Double encoding detection
- Mixed encoding variants

**Pattern Categories:**
- **XSS**: Script injection, event handlers, data URIs, CSS expressions
- **SQLi**: Union queries, boolean logic, time delays, error-based injection
- **CSRF**: State-changing parameters, redirect patterns
- **Phishing**: Typosquatting, suspicious TLDs, urgency keywords
- **Malware**: Suspicious file extensions, C2 patterns, download indicators

## 🐛 Troubleshooting

### Common Issues

**Permission Errors:**
```bash
# Linux: Run with appropriate permissions
sudo python browsertriage.py -u all -b all

# Windows: Run as Administrator
# Right-click Command Prompt -> Run as Administrator
```

**Browser Database Locked:**
```bash
# Close browser before extraction
pkill chrome firefox
# Or use remote extraction to bypass local locks
```

**Remote Connection Failures:**
```bash
# Windows: Verify WinRM is enabled
winrm quickconfig

# Linux: Verify SSH is running
sudo systemctl status ssh
```

**Missing Dependencies:**
```bash
# Install optional packages as needed
pip install pypsrp vt-py requests paramiko
```

### Verbose Logging

```bash
# Enable detailed logging for troubleshooting
python browsertriage.py -u alice -b chrome -v
```

## 📈 Example Analysis Workflow

### 1. Initial Triage
```bash
# Quick check of user's Chrome browser
python browsertriage.py -u suspect_user -b chrome --detect-all
```

### 2. Comprehensive Analysis  
```bash
# Full analysis with all services
python browsertriage.py -u suspect_user -b all --detect-all -ar -s -o ./case_001
```

### 3. Result Review
- Check `threat_report_*.csv` for immediate security alerts
- Review `browser_summary_*.csv` for timeline analysis
- Examine `detailed_threat_report_*.csv` for technical details

### 4. Follow-up Investigation
- Correlate timestamps with other log sources
- Investigate flagged URLs manually
- Check related user accounts if needed

## ⚠️ Disclaimer

This tool is intended for legitimate security research, incident response, and authorized security testing only. Users are responsible for:

- Obtaining proper authorization before analyzing systems
- Complying with applicable laws and regulations  
- Protecting sensitive data discovered during analysis
- Understanding the limitations of automated threat detection

The threat detection engine provides indicators that require human analysis and should not be considered definitive proof of malicious activity.

## 🤝 Contributing

This tool was developed as part of security research. Contributions welcome for:

- Additional browser support
- Enhanced detection patterns  
- New reputation sources
- Platform compatibility improvements
- Performance optimizations

## 📄 License

This project is provided for educational and research purposes. Please ensure compliance with applicable laws and organizational policies when using this tool.

---

**⚡ Quick Start**: `python browsertriage.py -u $USER -b all --detect-all`
