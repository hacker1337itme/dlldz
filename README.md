# dlldz
dlldz


# DLLDZ Windows DLL Hijacking Vulnerability Scanner - Complete Documentation by root

## 📋 Overview

The DLLDZ **Windows DLL Hijacking Vulnerability Scanner** is a comprehensive security auditing tool written in Go that identifies potential DLL (Dynamic Link Library) hijacking vulnerabilities across Windows systems. It scans multiple attack vectors, checks file permissions, analyzes registry settings, and provides actionable remediation steps while protecting against system crashes (BSOD).

## 🎯 Purpose

This scanner helps security professionals, system administrators, and penetration testers identify:
- Privilege escalation paths through DLL hijacking
- Missing security patches and misconfigurations
- Writable directories in trusted search paths
- Vulnerable service configurations
- Registry-based persistence mechanisms
- Printer driver vulnerabilities
- WinSxS assembly issues

## 🔍 Key Features

### 1. **Multi-Vector Scanning**
- **Running Processes**: Analyzes loaded DLLs in active processes
- **DLL Search Order**: Examines Windows DLL search order hijacking
- **KnownDLLs**: Checks registry-protected DLLs for writability
- **AppInit_DLLs**: Scans global DLL loading mechanisms
- **WinSxS**: Analyzes Side-by-Side assembly manifests
- **Service Paths**: Detects unquoted service path vulnerabilities
- **PATH Directories**: Scans environment PATH for writable locations
- **Printer Drivers**: Examines printer driver DLLs for vulnerabilities
- **Protected Paths**: Checks system-protected directories (with BSOD protection)

### 2. **BSOD Protection**
- **Safe Mode Operations**: Skips dangerous tests on critical system paths
- **Risk Assessment**: Evaluates potential for Blue Screen of Death
- **Process Whitelist**: Identifies high-risk processes (lsass.exe, winlogon.exe, etc.)
- **Read-Only Testing**: Uses temporary files for permission testing

### 3. **Registry Analysis**
- KnownDLLs registry key enumeration
- AppInit_DLLs configuration checking (32/64-bit)
- COM/hijacking registry analysis
- Service configuration validation

### 4. **Permission Checking**
- Writable directory detection
- File permission analysis
- ACL (Access Control List) evaluation
- Temporary file creation testing

### 5. **Manifest Parsing**
- XML-based WinSxS manifest analysis
- UTF-8/UTF-16 encoding detection
- COM class extraction from manifests
- Type library identification
- Window class enumeration
- CLR surrogate detection

### 6. **Report Generation**
- **Severity Classification**: Critical, High, Medium
- **Detailed Findings**: Process, DLL path, description
- **BSOD Risk Assessment**: Identifies crash-prone vulnerabilities
- **Mitigation Scripts**: Auto-generated batch files for fixing issues
- **Remediation Steps**: Actionable security recommendations

## 🏗️ Architecture

### Core Components

```
┌─────────────────────────────────────┐
│       Scanner Initialization         │
│  - Protected paths definition        │
│  - PATH environment parsing          │
│  - BSOD protection setup             │
└───────────────┬─────────────────────┘
                ▼
┌─────────────────────────────────────┐
│      Multi-Vector Scan Engine        │
├─────────────────────────────────────┤
│ • Process Scanner                    │
│ • Search Order Scanner               │
│ • KnownDLLs Scanner                  │
│ • AppInit Scanner                    │
│ • WinSxS Scanner                     │
│ • Service Scanner                    │
│ • PATH Scanner                       │
│ • Printer Driver Scanner             │
│ • Protected Path Scanner             │
└───────────────┬─────────────────────┘
                ▼
┌─────────────────────────────────────┐
│     Vulnerability Analysis           │
│  - Permission checking               │
│  - Existence verification            │
│  - Path validation                   │
│  - Risk assessment                   │
└───────────────┬─────────────────────┘
                ▼
┌─────────────────────────────────────┐
│        Report Generation             │
│  - Summary statistics                │
│  - Detailed findings                 │
│  - Mitigation scripts                │
│  - Remediation steps                 │
└─────────────────────────────────────┘
```

### Data Structures

```go
type Vulnerability struct {
    Type        VulnType    // MissingDLL, WritablePath, UnquotedPath, etc.
    Process     string      // Process name (e.g., "lsass.exe")
    ProcessPath string      // Full path to process executable
    DLLPath     string      // Path to vulnerable DLL
    TargetPath  string      // Target directory for hijacking
    Severity    string      // CRITICAL, HIGH, MEDIUM
    Description string      // Detailed vulnerability description
    BSODRisk    bool        // Potential for system crash
    Mitigation  string      // Remediation steps
    Exploitable bool        // Whether vulnerability is exploitable
}

type Scanner struct {
    vulnerabilities []Vulnerability  // Collected findings
    scanPaths       []string         // Directories to scan
    protectedPaths  []string         // System-protected paths
    bsodCheck       bool             // BSOD protection enabled
    safeMode        bool             // Safe operation mode
}

type DLLInfo struct {
    Name           string   // DLL filename
    Path           string   // Full path to DLL
    Hash           string   // File hash (MD5)
    HashAlg        string   // Hash algorithm used
    COMClasses     []string // Associated COM CLSIDs
    TypeLibs       []string // Type library IDs
    WindowClasses  []string // Window class names
    IsClrSurrogate bool     // CLR surrogate indicator
    IsDependency   bool     // Assembly dependency
    SourceManifest string   // Source manifest file
    Verified       bool     // Existence verified
}
```

## 🔬 Scan Types Detailed

### 1. **Process Scanner**
- Enumerates all running processes using `CreateToolhelp32Snapshot`
- Retrieves loaded modules for each process
- Checks if referenced DLLs exist on disk
- Tests write permissions on DLL files
- Identifies high-risk processes (LSASS, Winlogon, etc.)

### 2. **DLL Search Order Scanner**
Analyzes Windows DLL search order:
1. Application directory
2. System directory (C:\Windows\System32)
3. 16-bit system directory (C:\Windows\System)
4. Windows directory (C:\Windows)
5. Current directory
6. PATH environment directories

Tests commonly hijacked DLLs against writable directories in search path.

### 3. **KnownDLLs Scanner**
- Reads `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`
- Verifies if protected system DLLs are writable
- Checks for missing KnownDLL entries

### 4. **AppInit_DLLs Scanner**
- Examines both 32-bit and 64-bit registry locations:
  - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`
  - `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows`
- Checks `LoadAppInit_DLLs` configuration
- Validates existence and permissions of listed DLLs

### 5. **WinSxS Scanner**
- Analyzes Side-by-Side assembly manifests
- Parses XML manifests for DLL references
- Extracts COM classes, type libraries, window classes
- Verifies DLL existence in WinSxS store
- Checks for missing assembly dependencies

### 6. **Service Path Scanner**
- Uses WMIC to query service configurations
- Detects unquoted service paths with spaces
- Checks writability of service binary directories
- Identifies potential privilege escalation vectors

### 7. **PATH Directory Scanner**
- Parses system PATH environment variable
- Tests each directory for write permissions
- Checks ability to create test DLL files
- Identifies writable directories in trusted search paths

### 8. **Printer Driver Scanner**
- Scans printer driver directories
- Analyzes common printer DLLs
- Checks for missing printer drivers
- Tests permissions on printer driver files
- Examines printer driver isolation settings

### 9. **Protected Path Scanner**
- Checks critical system directories:
  - C:\Windows\System32
  - C:\Windows\SysWOW64
  - C:\Program Files
  - C:\Program Files (x86)
  - C:\Windows\WinSxS
- Tests for incorrect permissions
- Includes BSOD risk assessment

## 🛡️ Security Features

### BSOD Protection
```go
func (s *Scanner) checkBSODRisk(processName string) bool {
    highRiskProcesses := []string{
        "lsass.exe",      // Local Security Authority Subsystem
        "winlogon.exe",   // Windows Logon
        "csrss.exe",      // Client Server Runtime Process
        "services.exe",   // Service Control Manager
        "svchost.exe",    // Service Host
        "smss.exe",       // Session Manager
        "ntoskrnl.exe",   // Windows NT Kernel
    }
    // Returns true if process could cause BSOD
}
```

### Safe File Operations
```go
func (s *Scanner) safeFileOperation(path string, operation func() error) error {
    if s.bsodCheck && s.isSystemPath(path) {
        return fmt.Errorf("BSOD protection: skipping operation on system path")
    }
    return operation()
}
```

## 📊 Report Generation

### Summary Statistics
- Total vulnerabilities found
- Breakdown by severity (Critical/High/Medium)
- BSOD risk assessment

### Detailed Findings
Each vulnerability includes:
- **Type**: Missing DLL, writable path, unquoted service, etc.
- **Process**: Affected process or component
- **Location**: DLL path or target directory
- **Severity**: CRITICAL, HIGH, MEDIUM
- **Description**: Detailed explanation
- **BSOD Risk**: Yes/No with explanation
- **Mitigation**: Step-by-step remediation
- **Exploitable**: Confirmed exploitable

### Mitigation Script Generation
Automatically creates batch files with:
- `icacls` commands to fix permissions
- Registry hardening commands
- Service configuration fixes
- Permission restoration scripts

## 🚀 Usage Examples

### Basic Scan
```bash
# Run with default settings (BSOD protection enabled)
dll_scanner.exe
```

### Administrative Scan
```bash
# Run as administrator for full access
runas /user:Administrator "dll_scanner.exe"
```

### Sample Output
```
Windows DLL Hijacking Vulnerability Scanner
===========================================
BSOD Protection: ENABLED - Safe mode operations only

[*] Starting comprehensive DLL hijacking scan...
[*] BSOD protection active - testing only non-critical paths

[*] Scanning running processes...
[*] Scanning DLL search order hijacking vectors...
[*] Scanning KnownDLLs registry for hijacking vectors...
[*] Scanning AppInit_DLLs for hijacking vectors...
[*] Scanning WinSxS for vulnerabilities...
[*] Scanning unquoted service paths...
[*] Scanning PATH directories for writability...
[*] Scanning printer driver directories for DLLs...

============================================================
SCAN COMPLETE - VULNERABILITY REPORT
============================================================

Vulnerability Summary:
  Critical: 2
  High:     5
  Medium:   3

Detailed Vulnerabilities:
------------------------------------------------------------
[1] CRITICAL - AppInit_DLL not found - hijack possible
    Process: AppInit
    DLL: C:\Windows\System32\malicious.dll
    BSOD Risk: true
    Mitigation: Remove invalid AppInit_DLLs registry entries

[2] HIGH - PATH directory is writable - DLL hijacking possible
    Process: System
    Target: C:\Users\user\AppData\Local\Temp
    BSOD Risk: false
    Mitigation: Remove write permissions from PATH directories

[+] Mitigation script saved as: mitigate_dll_hijacking.bat
```

## 🔧 Mitigation Strategies

### Permission Fixes
```batch
icacls "C:\vulnerable\path" /inheritance:e /T
icacls "C:\vulnerable\path" /remove:g "Users" /T
icacls "C:\vulnerable\path" /remove:g "Authenticated Users" /T
```

### Registry Hardening
```batch
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v SafeDllSearchMode /t REG_DWORD /d 1 /f
```

### Service Configuration
```batch
sc config "VulnerableService" binPath= "\"C:\Program Files\Secure Path\service.exe\""
```

## ⚠️ Limitations

1. **Administrator Privileges Required**: Some scans need admin rights
2. **Performance Impact**: Scanning all processes may be slow on busy systems
3. **False Positives**: Some writable paths may be legitimate
4. **Windows Version Differences**: Registry paths vary between Windows versions
5. **Antivirus Interference**: AV may block file permission tests

## 🔒 Security Considerations

- **Ethical Use Only**: Authorized security testing only
- **Data Privacy**: No sensitive data is transmitted
- **System Safety**: BSOD protection prevents crashes
- **Read-Only Operations**: No permanent system changes

## 📚 Dependencies

- `golang.org/x/sys/windows`: Windows system calls
- `golang.org/x/sys/windows/registry`: Registry access
- `golang.org/x/text/encoding/unicode`: Unicode handling
- `golang.org/x/text/transform`: Text encoding conversion

## 🎓 Educational Value

This scanner demonstrates:
- Windows DLL loading mechanics
- Privilege escalation techniques
- Security misconfiguration analysis
- Windows internals (processes, services, registry)
- Go programming for system utilities
- Security assessment methodologies

## 📝 Conclusion

The Windows DLL Hijacking Vulnerability Scanner is a powerful tool for identifying and mitigating one of the most common Windows privilege escalation vectors. Its comprehensive approach, BSOD protection, and actionable reporting make it invaluable for security assessments and hardening Windows systems.
