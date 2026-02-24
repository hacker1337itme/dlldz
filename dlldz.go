// dlldz.go
package main

import (
    "crypto/md5"
    "encoding/hex"
    "encoding/xml"
    "fmt"
    "io"
    "os"
    "os/exec"
    "path/filepath"
    "reflect"  
    "regexp"
    "strings"
    "syscall"
    "time"
    "unsafe"
    
    "golang.org/x/sys/windows"
    "golang.org/x/sys/windows/registry"
    "golang.org/x/text/encoding/unicode"
    "golang.org/x/text/transform"
)

// Windows API structures
type (
    PROCESS_MITIGATION_POLICY uint32
)

const (
    // Process mitigation policies
    ProcessDEPPolicy           PROCESS_MITIGATION_POLICY = 0
    ProcessASLRPolicy          PROCESS_MITIGATION_POLICY = 1
    ProcessDynamicCodePolicy   PROCESS_MITIGATION_POLICY = 2
    ProcessStrictHandleCheckPolicy PROCESS_MITIGATION_POLICY = 3
    ProcessSystemCallDisablePolicy PROCESS_MITIGATION_POLICY = 4
    ProcessMitigationOptionsMask   PROCESS_MITIGATION_POLICY = 5
    ProcessExtensionPointDisablePolicy PROCESS_MITIGATION_POLICY = 6
    ProcessSignaturePolicy      PROCESS_MITIGATION_POLICY = 8
    ProcessFontDisablePolicy    PROCESS_MITIGATION_POLICY = 10
    ProcessImageLoadPolicy      PROCESS_MITIGATION_POLICY = 11
)

// Vulnerability types
type VulnType int

const (
    MissingDLL VulnType = iota
    WritablePath
    UnquotedPath
    DLLHijacking
    RelativePath
    KnownDLLHijack
    SystemProtected
)

type Vulnerability struct {
    Type        VulnType
    Process     string
    ProcessPath string
    DLLPath     string
    TargetPath  string
    Severity    string
    Description string
    BSODRisk    bool
    Mitigation  string
    Exploitable bool
}

type Scanner struct {
    vulnerabilities []Vulnerability
    scanPaths       []string
    protectedPaths  []string
    bsodCheck       bool
    safeMode        bool
}

// SxS Manifest structures
type Assembly struct {
    XMLName          xml.Name         `xml:"assembly"`
    ManifestVersion  string            `xml:"manifestVersion,attr"`
    AssemblyIdentity AssemblyIdentity  `xml:"assemblyIdentity"`
    Files            []File            `xml:"file"`
    Dependency       []Dependency      `xml:"dependency"`
    ClrSurrogate     []ClrSurrogate    `xml:"clrSurrogate"`
    WindowsSettings  *WindowsSettings  `xml:"windowsSettings"`
}

type AssemblyIdentity struct {
    XMLName         xml.Name `xml:"assemblyIdentity"`
    Type            string    `xml:"type,attr"`
    Name            string    `xml:"name,attr"`
    Language        string    `xml:"language,attr"`
    ProcessorArch   string    `xml:"processorArchitecture,attr"`
    Version         string    `xml:"version,attr"`
    PublicKeyToken  string    `xml:"publicKeyToken,attr"`
    BuildType       string    `xml:"buildType,attr"`
}

type File struct {
    XMLName xml.Name `xml:"file"`
    Name    string   `xml:"name,attr"`
    Hash    string   `xml:"hash,attr"`
    Hashalg string   `xml:"hashalg,attr"`
    
    // Nested elements
    COMClass          []COMClass          `xml:"comClass"`
    COMInterfaceProxy []COMInterfaceProxy `xml:"comInterfaceProxy"`
    TypeLibrary       []TypeLibrary       `xml:"typelib"`
    WindowClass       []WindowClass       `xml:"windowClass"`
}

type COMClass struct {
    CLSID           string `xml:"clsid,attr"`
    ThreadingModel  string `xml:"threadingModel,attr"`
    ProgID          string `xml:"progid,attr"`
    Description     string `xml:"description,attr"`
}

type COMInterfaceProxy struct {
    IID         string `xml:"iid,attr"`
    Name        string `xml:"name,attr"`
    ProxyStubCLSID string `xml:"proxyStubClsid32,attr"`
}

type TypeLibrary struct {
    LIBID       string `xml:"libid,attr"`
    Version     string `xml:"version,attr"`
    HelpDir     string `xml:"helpdir,attr"`
    ResourceID  string `xml:"resourceid,attr"`
    Flags       string `xml:"flags,attr"`
}

type WindowClass struct {
    Versioned    string `xml:"versioned,attr"`
    ClassName    string `xml:"classname,attr"`
}

type Dependency struct {
    XMLName             xml.Name            `xml:"dependency"`
    DependentAssembly   DependentAssembly   `xml:"dependentAssembly"`
}

type DependentAssembly struct {
    XMLName             xml.Name            `xml:"dependentAssembly"`
    AssemblyIdentity    AssemblyIdentity    `xml:"assemblyIdentity"`
}

type ClrSurrogate struct {
    XMLName     xml.Name `xml:"clrSurrogate"`
    CLSID       string   `xml:"clsid,attr"`
    DllName      string   `xml:"dllName,attr"`
}

type WindowsSettings struct {
    XMLName                     xml.Name                      `xml:"windowsSettings"`
    DpiAware                    *DpiAware                     `xml:"dpiAware"`
    DpiAwareness                *DpiAwareness                 `xml:"dpiAwareness"`
    AutoElevate                 *AutoElevate                  `xml:"autoElevate"`
    DisableTheming              *DisableTheming               `xml:"disableTheming"`
    DisableWindowFiltering      *DisableWindowFiltering       `xml:"disableWindowFiltering"`
    HighResolutionScrolling     *HighResolutionScrolling      `xml:"highResolutionScrolling"`
    UltraHighResolutionScrolling *UltraHighResolutionScrolling `xml:"ultraHighResolutionScrolling"`
    PrinterDriverIsolation      *PrinterDriverIsolation       `xml:"printerDriverIsolation"`
}

type DpiAware struct {
    XMLName xml.Name `xml:"dpiAware"`
    Value   string   `xml:",innerxml"`
}

type DpiAwareness struct {
    XMLName xml.Name `xml:"dpiAwareness"`
    Value   string   `xml:",innerxml"`
}

type AutoElevate struct {
    XMLName xml.Name `xml:"autoElevate"`
    Value   string   `xml:",innerxml"`
}

type DisableTheming struct {
    XMLName xml.Name `xml:"disableTheming"`
    Value   string   `xml:",innerxml"`
}

type DisableWindowFiltering struct {
    XMLName xml.Name `xml:"disableWindowFiltering"`
    Value   string   `xml:",innerxml"`
}

type HighResolutionScrolling struct {
    XMLName xml.Name `xml:"highResolutionScrolling"`
    Value   string   `xml:",innerxml"`
}

type UltraHighResolutionScrolling struct {
    XMLName xml.Name `xml:"ultraHighResolutionScrolling"`
    Value   string   `xml:",innerxml"`
}

type PrinterDriverIsolation struct {
    XMLName xml.Name `xml:"printerDriverIsolation"`
    Value   string   `xml:",innerxml"`
}

// Extracted DLL information
type DLLInfo struct {
    Name           string
    Path           string
    Hash           string
    HashAlg        string
    COMClasses     []string
    TypeLibs       []string
    WindowClasses  []string
    IsClrSurrogate bool
    IsDependency   bool
    SourceManifest string
    Verified       bool
}

func main() {
    fmt.Println("Windows DLL Hijacking Vulnerability Scanner")
    fmt.Println("===========================================")
    fmt.Println("BSOD Protection: ENABLED - Safe mode operations only\n")
    
    scanner := NewScanner(true) // Enable BSOD protection
    
    // Check if running with admin privileges
    if !isAdmin() {
        fmt.Println("[!] Warning: Running without administrator privileges")
        fmt.Println("[!] Some scans may be limited\n")
    }
    
    // Initialize scanner
    scanner.initializePaths()
    
    // Perform scans
    scanner.scanAll()
    
    // Generate report
    scanner.generateReport()
}

func NewScanner(bsodProtection bool) *Scanner {
    return &Scanner{
        vulnerabilities: make([]Vulnerability, 0),
        bsodCheck:       bsodProtection,
        safeMode:        true,
        protectedPaths: []string{
            "C:\\Windows\\System32",
            "C:\\Windows\\SysWOW64",
            "C:\\Windows\\System",
            "C:\\Windows\\SystemResources",
            "C:\\Program Files",
            "C:\\Program Files (x86)",
            "C:\\Windows\\WinSxS",
        },
    }
}

func (s *Scanner) initializePaths() {
    // Get system PATH environment variable
    path := os.Getenv("PATH")
    s.scanPaths = append(s.scanPaths, strings.Split(path, ";")...)
    
    // Add common Windows directories
    s.scanPaths = append(s.scanPaths,
        "C:\\Windows\\System32",
        "C:\\Windows\\SysWOW64",
        "C:\\Windows",
        "C:\\Program Files",
        "C:\\Program Files (x86)",
        filepath.Join(os.Getenv("APPDATA")),
        filepath.Join(os.Getenv("LOCALAPPDATA")),
        filepath.Join(os.Getenv("ProgramData")),
        "C:\\Windows\\Temp",
        os.Getenv("TEMP"),
        os.Getenv("TMP"),
    )
    
    // Remove duplicates
    s.scanPaths = unique(s.scanPaths)
}

func (s *Scanner) scanAll() {
    fmt.Println("[*] Starting comprehensive DLL hijacking scan...")
    fmt.Println("[*] BSOD protection active - testing only non-critical paths\n")
    
    // Scan running processes
    s.scanRunningProcesses()
    
    // Scan DLL search order hijacking
    s.scanDLLSearchOrder()
    
    // Scan known DLLs
    s.scanKnownDLLs()
    
    // Scan registry for AppInit_DLLs
    s.scanAppInitDLLs()
    
    // Scan WinSxS for vulnerabilities
    s.scanWinSxS()
    
    // Scan for unquoted service paths
    s.scanUnquotedServicePaths()
    
    // Scan PATH directories for writability
    s.scanPathDirectories()
    
    // Scan printer driver vulnerabilities 
    s.scanPrinterDriverVulnerabilities()


    // Scan system protected paths (with BSOD check)
    if !s.bsodCheck {
        s.scanProtectedPaths()
    }
}

// scanPrinterDriverDLLs scans the system for printer driver DLLs
func scanPrinterDriverDLLs() []string {
    var printerDLLs []string
    
    // Common printer driver directories
    printerDirs := []string{
        "C:\\Windows\\System32\\spool\\drivers",
        "C:\\Windows\\System32\\spool\\drivers\\x64",
        "C:\\Windows\\System32\\spool\\drivers\\w32x86",
        "C:\\Windows\\System32\\spool\\drivers\\color",
    }
    
    // Common printer driver DLLs
    commonPrinterDLLs := []string{
        "unidrv.dll",
        "unidrvui.dll",
        "pscript.dll",
        "pscript5.dll",
        "rasdd.dll",
        "rasddui.dll",
        "truetype.dll",
        "mxdwdrv.dll",
        "pdfmon.dll",
        "xpsdrv.dll",
        "xpsdrvui.dll",
        "p5ins.dll",
        "p5insui.dll",
        "pclxl.dll",
        "pcl5eres.dll",
        "pcl6.dll",
        "pcl6ui.dll",
    }
    
    // Check common printer driver directories
    for _, dir := range printerDirs {
        if _, err := os.Stat(dir); err == nil {
            filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
                if err != nil {
                    return nil
                }
                if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".dll") {
                    printerDLLs = append(printerDLLs, path)
                }
                return nil
            })
        }
    }
    
    // Also check for common printer DLLs in System32
    for _, dll := range commonPrinterDLLs {
        sys32Path := filepath.Join("C:\\Windows\\System32", dll)
        if _, err := os.Stat(sys32Path); err == nil {
            printerDLLs = append(printerDLLs, sys32Path)
        }
        
        syswow64Path := filepath.Join("C:\\Windows\\SysWOW64", dll)
        if _, err := os.Stat(syswow64Path); err == nil {
            printerDLLs = append(printerDLLs, syswow64Path)
        }
    }
    
    return printerDLLs
}

// Add this method to the Scanner struct
func (s *Scanner) scanPrinterDriverVulnerabilities() {
    fmt.Println("\n[*] Scanning printer driver DLLs for vulnerabilities...")
    
    printerDLLs := scanPrinterDriverDLLs()
    
    for _, dllPath := range printerDLLs {
        // Check if DLL is missing
        if _, err := os.Stat(dllPath); os.IsNotExist(err) {
            s.vulnerabilities = append(s.vulnerabilities, Vulnerability{
                Type:        MissingDLL,
                Process:     "Printer Driver",
                DLLPath:     dllPath,
                Severity:    "HIGH",
                Description: "Printer driver DLL not found - potential hijacking point",
                BSODRisk:    true,
                Exploitable: true,
                Mitigation:  "Reinstall printer drivers or run sfc /scannow",
            })
            continue
        }
        
        // Check writability
        if s.isWritable(dllPath) && !s.isProtectedPath(dllPath) {
            s.vulnerabilities = append(s.vulnerabilities, Vulnerability{
                Type:        WritablePath,
                Process:     "Printer Driver",
                DLLPath:     dllPath,
                Severity:    "CRITICAL",
                Description: "Printer driver DLL is writable - potential privilege escalation",
                BSODRisk:    true,
                Exploitable: true,
                Mitigation:  "Restrict write permissions on printer driver DLLs",
            })
        }
        
        // Check if in PATH directory
        for _, pathDir := range s.scanPaths {
            if strings.HasPrefix(strings.ToLower(dllPath), strings.ToLower(pathDir)) {
                if s.isWritable(pathDir) {
                    s.vulnerabilities = append(s.vulnerabilities, Vulnerability{
                        Type:        DLLHijacking,
                        Process:     "Printer Driver",
                        DLLPath:     dllPath,
                        TargetPath:  pathDir,
                        Severity:    "HIGH",
                        Description: "Printer driver DLL in writable PATH directory",
                        BSODRisk:    true,
                        Exploitable: true,
                        Mitigation:  "Remove write permissions from PATH directory",
                    })
                }
                break
            }
        }
    }
}

func (s *Scanner) scanRunningProcesses() {
    fmt.Println("\n[*] Scanning running processes...")
    
    processes, err := getProcessList()
    if err != nil {
        fmt.Printf("[!] Error getting process list: %v\n", err)
        return
    }
    
    for _, proc := range processes {
        // Get loaded DLLs for each process
        dlls, err := getProcessModules(proc.ProcessID)
        if err != nil {
            continue
        }
        
        for _, dll := range dlls {
            // Check if DLL exists and is writable
            if _, err := os.Stat(dll); os.IsNotExist(err) {
                s.vulnerabilities = append(s.vulnerabilities, Vulnerability{
                    Type:        MissingDLL,
                    Process:     proc.Name,
                    ProcessPath: proc.ExecPath,
                    DLLPath:     dll,
                    Severity:    "HIGH",
                    Description: "DLL not found - potential hijacking point",
                    BSODRisk:    s.checkBSODRisk(proc.Name),
                    Exploitable: true,
                    Mitigation:  "Install missing DLL or verify file permissions",
                })
                continue
            }
            
            // Check writability
            if s.isWritable(dll) && !s.isProtectedPath(dll) {
                s.vulnerabilities = append(s.vulnerabilities, Vulnerability{
                    Type:        WritablePath,
                    Process:     proc.Name,
                    ProcessPath: proc.ExecPath,
                    DLLPath:     dll,
                    Severity:    "CRITICAL",
                    Description: "DLL writable by non-admin users",
                    BSODRisk:    s.checkBSODRisk(proc.Name),
                    Exploitable: true,
                    Mitigation:  "Restrict write permissions on DLL file",
                })
            }
        }
    }
}

func (s *Scanner) scanDLLSearchOrder() {
    fmt.Println("\n[*] Scanning DLL search order hijacking vectors...")
    
    // Common DLLs that are often hijacked
    hijackableDLLs := []string{
        "version.dll",
        "dbghelp.dll",
        "wlanapi.dll",
        "ws2_32.dll",
        "crypt32.dll",
        "winhttp.dll",
        "wininet.dll",
        "dnsapi.dll",
        "iphlpapi.dll",
        "secur32.dll",
        "credui.dll",
        "netapi32.dll",
        "ole32.dll",
        "shell32.dll",
        "shlwapi.dll",
        "user32.dll",
        "gdi32.dll",
        "advapi32.dll",
        "kernel32.dll",
        "ntdll.dll",
    }
    
    searchOrder := []string{
        "1. Application directory",
        "2. System directory (C:\\Windows\\System32)",
        "3. 16-bit system directory (C:\\Windows\\System)",
        "4. Windows directory (C:\\Windows)",
        "5. Current directory",
        "6. PATH environment directories",
    }
    
    fmt.Println("[*] Search order:")
    for _, order := range searchOrder {
        fmt.Printf("    %s\n", order)
    }
    
    // Check writable directories in search path
    appDirs := []string{
        filepath.Dir(os.Args[0]),
        ".",
        "C:\\Windows\\System32",
        "C:\\Windows",
        "C:\\",
    }
    
    for _, dll := range hijackableDLLs {
        for _, dir := range appDirs {
            testPath := filepath.Join(dir, dll)
            
            // Check if we can write to this location
            if s.isWritable(dir) && !s.isProtectedPath(dir) {
                s.vulnerabilities = append(s.vulnerabilities, Vulnerability{
                    Type:        DLLHijacking,
                    Process:     "Multiple",
                    DLLPath:     dll,
                    TargetPath:  testPath,
                    Severity:    "HIGH",
                    Description: fmt.Sprintf("DLL hijacking possible for %s in %s", dll, dir),
                    BSODRisk:    false,
                    Exploitable: true,
                    Mitigation:  "Remove write permissions from search path directories",
                })
            }
        }
    }
}

func (s *Scanner) scanKnownDLLs() {
    fmt.Println("\n[*] Scanning KnownDLLs registry for hijacking vectors...")
    
    k, err := registry.OpenKey(registry.LOCAL_MACHINE,
        `SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`,
        registry.QUERY_VALUE)
    if err != nil {
        fmt.Printf("[!] Failed to open KnownDLLs key: %v\n", err)
        return
    }
    defer k.Close()
    
    values, err := k.ReadValueNames(0)
    if err != nil {
        fmt.Printf("[!] Failed to read KnownDLLs values: %v\n", err)
        return
    }
    
    for _, value := range values {
        dllPath, _, err := k.GetStringValue(value)
        if err != nil {
            continue
        }
        
        // Check if KnownDLL is writable
        fullPath := filepath.Join("C:\\Windows\\System32", dllPath)
        if s.isWritable(fullPath) {
            s.vulnerabilities = append(s.vulnerabilities, Vulnerability{
                Type:        KnownDLLHijack,
                Process:     "System",
                DLLPath:     fullPath,
                Severity:    "CRITICAL",
                Description: "KnownDLL is writable - potential system-wide hijack",
                BSODRisk:    true,
                Exploitable: true,
                Mitigation:  "Restrict write permissions on KnownDLLs",
            })
        }
    }
}

func (s *Scanner) scanAppInitDLLs() {
    fmt.Println("\n[*] Scanning AppInit_DLLs for hijacking vectors...")
    
    // Check 32-bit and 64-bit registry locations
    keys := []registry.Key{
        registry.LOCAL_MACHINE,
        registry.CURRENT_USER,
    }
    
    paths := []string{
        `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`,
        `SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows`,
    }
    
    for _, key := range keys {
        for _, path := range paths {
            k, err := registry.OpenKey(key, path, registry.QUERY_VALUE)
            if err != nil {
                continue
            }
            
            appInitDLLs, _, err := k.GetStringValue("AppInit_DLLs")
            if err != nil {
                k.Close()
                continue
            }
            
            loadAppInit, _, err := k.GetIntegerValue("LoadAppInit_DLLs")
            if err != nil {
                loadAppInit = 0
            }
            
            if appInitDLLs != "" {
                dllList := strings.Split(appInitDLLs, " ")
                for _, dll := range dllList {
                    if dll == "" {
                        continue
                    }
                    
                    // Check if DLL exists and is writable
                    if _, err := os.Stat(dll); os.IsNotExist(err) {
                        s.vulnerabilities = append(s.vulnerabilities, Vulnerability{
                            Type:        MissingDLL,
                            Process:     "AppInit",
                            DLLPath:     dll,
                            Severity:    "CRITICAL",
                            Description: "AppInit_DLL not found - hijack possible",
                            BSODRisk:    loadAppInit == 1,
                            Exploitable: true,
                            Mitigation:  "Remove invalid AppInit_DLLs registry entries",
                        })
                    } else if s.isWritable(dll) {
                        s.vulnerabilities = append(s.vulnerabilities, Vulnerability{
                            Type:        WritablePath,
                            Process:     "AppInit",
                            DLLPath:     dll,
                            Severity:    "CRITICAL",
                            Description: "AppInit_DLL writable - system-wide hijack",
                            BSODRisk:    loadAppInit == 1,
                            Exploitable: true,
                            Mitigation:  "Restrict write permissions on AppInit_DLLs",
                        })
                    }
                }
            }
            
            k.Close()
        }
    }
}

func (s *Scanner) scanWinSxS() {
    fmt.Println("\n[*] Scanning WinSxS for vulnerabilities...")
    
    winsxsPath := "C:\\Windows\\WinSxS"
    
    // Check if WinSxS is writable (should never happen)
    if s.isWritable(winsxsPath) {
        s.vulnerabilities = append(s.vulnerabilities, Vulnerability{
            Type:        SystemProtected,
            Process:     "System",
            DLLPath:     winsxsPath,
            Severity:    "CRITICAL",
            Description: "WinSxS directory is writable - severe vulnerability",
            BSODRisk:    true,
            Exploitable: true,
            Mitigation:  "Immediately restore WinSxS permissions",
        })
    }
    
    // Check manifest files for missing DLLs
    manifests, _ := filepath.Glob(filepath.Join(winsxsPath, "Manifests", "*.manifest"))
    for i, manifest := range manifests {
        if i > 10 { // Limit scan to avoid performance issues
            break
        }
        
        dlls, err := extractDLLsFromManifest(manifest)
        if err == nil {
            for _, dll := range dlls {
                fullPath := filepath.Join(winsxsPath, dll)
                if _, err := os.Stat(fullPath); os.IsNotExist(err) {
                    s.vulnerabilities = append(s.vulnerabilities, Vulnerability{
                        Type:        MissingDLL,
                        Process:     "SxS",
                        DLLPath:     fullPath,
                        Severity:    "HIGH",
                        Description: "Missing WinSxS DLL - potential hijack",
                        BSODRisk:    true,
                        Exploitable: true,
                        Mitigation:  "Run System File Checker (sfc /scannow)",
                    })
                }
            }
        }
    }
}

func (s *Scanner) scanUnquotedServicePaths() {
    fmt.Println("\n[*] Scanning unquoted service paths...")
    
    cmd := exec.Command("wmic", "service", "get", "name,displayname,pathname,startmode", "/format:csv")
    output, err := cmd.Output()
    if err != nil {
        fmt.Printf("[!] Failed to query services: %v\n", err)
        return
    }
    
    lines := strings.Split(string(output), "\n")
    for _, line := range lines {
        if strings.Contains(line, ".exe") && strings.Contains(line, " ") {
            parts := strings.Split(line, ",")
            if len(parts) >= 3 {
                servicePath := parts[2]
                if !strings.HasPrefix(servicePath, "\"") && strings.Contains(servicePath, " ") {
                    // Unquoted path vulnerability
                    pathParts := strings.Split(servicePath, " ")
                    if len(pathParts) > 0 {
                        vulnPath := pathParts[0]
                        if s.isWritable(filepath.Dir(vulnPath)) {
                            s.vulnerabilities = append(s.vulnerabilities, Vulnerability{
                                Type:        UnquotedPath,
                                Process:     parts[0],
                                TargetPath:  servicePath,
                                Severity:    "HIGH",
                                Description: "Unquoted service path with writable directory",
                                BSODRisk:    false,
                                Exploitable: true,
                                Mitigation:  "Quote service path or restrict directory permissions",
                            })
                        }
                    }
                }
            }
        }
    }
}

func (s *Scanner) scanPathDirectories() {
    fmt.Println("\n[*] Scanning PATH directories for writability...")
    
    for _, path := range s.scanPaths {
        if path == "" {
            continue
        }
        
        // Check if directory is writable
        if s.isWritable(path) && !s.isProtectedPath(path) {
            // Test DLL planting in this directory
            testDLL := filepath.Join(path, "test_hijack.dll")
            if s.canCreateFile(testDLL) {
                s.vulnerabilities = append(s.vulnerabilities, Vulnerability{
                    Type:        WritablePath,
                    Process:     "System",
                    TargetPath:  path,
                    Severity:    "HIGH",
                    Description: "PATH directory is writable - DLL hijacking possible",
                    BSODRisk:    s.isSystemPath(path),
                    Exploitable: true,
                    Mitigation:  "Remove write permissions from PATH directories",
                })
            }
        }
    }
}

func (s *Scanner) scanProtectedPaths() {
    fmt.Println("\n[*] Scanning protected system paths (HIGH RISK - BSOD POSSIBLE)...")
    
    for _, path := range s.protectedPaths {
        if s.isWritable(path) {
            s.vulnerabilities = append(s.vulnerabilities, Vulnerability{
                Type:        SystemProtected,
                Process:     "System",
                TargetPath:  path,
                Severity:    "CRITICAL",
                Description: "Protected system path is writable - BSOD risk",
                BSODRisk:    true,
                Exploitable: true,
                Mitigation:  "IMMEDIATE: Restore protected permissions",
            })
        }
    }
}

func (s *Scanner) checkBSODRisk(processName string) bool {
    highRiskProcesses := []string{
        "lsass.exe",
        "winlogon.exe",
        "csrss.exe",
        "services.exe",
        "svchost.exe",
        "smss.exe",
        "kernel.exe",
        "system.exe",
        "ntoskrnl.exe",
    }
    
    for _, proc := range highRiskProcesses {
        if strings.EqualFold(processName, proc) {
            return true
        }
    }
    return false
}

func (s *Scanner) isProtectedPath(path string) bool {
    for _, protected := range s.protectedPaths {
        if strings.HasPrefix(strings.ToLower(path), strings.ToLower(protected)) {
            return true
        }
    }
    return false
}

func (s *Scanner) isSystemPath(path string) bool {
    systemPaths := []string{
        "C:\\Windows",
        "C:\\Program Files",
        "C:\\Program Files (x86)",
    }
    
    for _, sysPath := range systemPaths {
        if strings.HasPrefix(strings.ToLower(path), strings.ToLower(sysPath)) {
            return true
        }
    }
    return false
}

func (s *Scanner) isWritable(path string) bool {
    // Check if path exists
    info, err := os.Stat(path)
    if err != nil {
        return false
    }
    
    if !info.IsDir() {
        path = filepath.Dir(path)
    }
    
    // Try to create a temporary file to test write permissions
    testFile := filepath.Join(path, ".write_test_"+fmt.Sprintf("%d", time.Now().UnixNano()))
    f, err := os.Create(testFile)
    if err != nil {
        return false
    }
    f.Close()
    os.Remove(testFile)
    return true
}

func (s *Scanner) canCreateFile(path string) bool {
    f, err := os.Create(path)
    if err != nil {
        return false
    }
    f.Close()
    os.Remove(path)
    return true
}

func (s *Scanner) generateReport() {
    fmt.Println("\n" + strings.Repeat("=", 60))
    fmt.Println("SCAN COMPLETE - VULNERABILITY REPORT")
    fmt.Println(strings.Repeat("=", 60))
    
    if len(s.vulnerabilities) == 0 {
        fmt.Println("\n[+] No DLL hijacking vulnerabilities found!")
        return
    }
    
    // Group by severity
    critical := 0
    high := 0
    medium := 0
    
    for _, vuln := range s.vulnerabilities {
        switch vuln.Severity {
        case "CRITICAL":
            critical++
        case "HIGH":
            high++
        default:
            medium++
        }
    }
    
    fmt.Printf("\nVulnerability Summary:\n")
    fmt.Printf("  Critical: %d\n", critical)
    fmt.Printf("  High:     %d\n", high)
    fmt.Printf("  Medium:   %d\n\n", medium)
    
    // Detailed report
    fmt.Println("Detailed Vulnerabilities:")
    fmt.Println(strings.Repeat("-", 60))
    
    for i, vuln := range s.vulnerabilities {
        fmt.Printf("[%d] %s - %s\n", i+1, vuln.Severity, vuln.Description)
        fmt.Printf("    Process: %s\n", vuln.Process)
        if vuln.DLLPath != "" {
            fmt.Printf("    DLL: %s\n", vuln.DLLPath)
        }
        if vuln.TargetPath != "" {
            fmt.Printf("    Target: %s\n", vuln.TargetPath)
        }
        fmt.Printf("    BSOD Risk: %v\n", vuln.BSODRisk)
        fmt.Printf("    Mitigation: %s\n", vuln.Mitigation)
        fmt.Println()
    }
    
    // Generate mitigation script
    s.generateMitigationScript()
}

func (s *Scanner) generateMitigationScript() {
    script := "@echo off\n"
    script += "REM DLL Hijacking Mitigation Script\n"
    script += "REM Run as Administrator\n\n"
    
    for _, vuln := range s.vulnerabilities {
        if vuln.Type == WritablePath && vuln.TargetPath != "" {
            script += fmt.Sprintf("icacls \"%s\" /inheritance:e /T\n", vuln.TargetPath)
            script += fmt.Sprintf("icacls \"%s\" /remove:g \"Users\" /T\n", vuln.TargetPath)
            script += fmt.Sprintf("icacls \"%s\" /remove:g \"Authenticated Users\" /T\n\n", vuln.TargetPath)
        }
    }
    
    err := os.WriteFile("mitigate_dll_hijacking.bat", []byte(script), 0644)
    if err == nil {
        fmt.Println("[+] Mitigation script saved as: mitigate_dll_hijacking.bat")
    }
}

// Helper functions
func isAdmin() bool {
    _, err := os.Open("\\\\.\\PHYSICALDRIVE0")
    return err == nil
}

func unique(slice []string) []string {
    keys := make(map[string]bool)
    list := []string{}
    for _, entry := range slice {
        if _, value := keys[entry]; !value {
            keys[entry] = true
            list = append(list, entry)
        }
    }
    return list
}

type ProcessInfo struct {
    Name      string
    ProcessID uint32
    ExecPath  string
}

func getProcessList() ([]ProcessInfo, error) {
    processes := make([]ProcessInfo, 0)
    
    snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
    if err != nil {
        return nil, err
    }
    defer windows.CloseHandle(snapshot)
    
    var pe windows.ProcessEntry32
    pe.Size = uint32(unsafe.Sizeof(pe))
    
    err = windows.Process32First(snapshot, &pe)
    if err != nil {
        return nil, err
    }
    
    for {
        procName := windows.UTF16ToString(pe.ExeFile[:])
        processes = append(processes, ProcessInfo{
            Name:      procName,
            ProcessID: pe.ProcessID,
            ExecPath:  getProcessPath(pe.ProcessID),
        })
        
        err = windows.Process32Next(snapshot, &pe)
        if err != nil {
            break
        }
    }
    
    return processes, nil
}

func getProcessPath(pid uint32) string {
    // Try to get full process path
    handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
    if err != nil {
        return ""
    }
    defer windows.CloseHandle(handle)
    
    path := make([]uint16, windows.MAX_PATH)
    size := uint32(len(path))
    
    err = windows.QueryFullProcessImageName(handle, 0, &path[0], &size)
    if err != nil {
        return ""
    }
    
    return windows.UTF16ToString(path[:size])
}

func getProcessModules(pid uint32) ([]string, error) {
    modules := make([]string, 0)
    
    snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, pid)
    if err != nil {
        return nil, err
    }
    defer windows.CloseHandle(snapshot)
    
    var me windows.ModuleEntry32
    me.Size = uint32(unsafe.Sizeof(me))
    
    err = windows.Module32First(snapshot, &me)
    if err != nil {
        return nil, err
    }
    
    for {
        modulePath := windows.UTF16ToString(me.ExePath[:])
        if modulePath != "" {
            modules = append(modules, modulePath)
        }
        
        err = windows.Module32Next(snapshot, &me)
        if err != nil {
            break
        }
    }
    
    return modules, nil
}

// Security check for dangerous operations
func (s *Scanner) safeFileOperation(path string, operation func() error) error {
    if s.bsodCheck && s.isSystemPath(path) {
        return fmt.Errorf("BSOD protection: skipping operation on system path")
    }
    return operation()
}

// DLL Manifest Parser Functions

// Main extraction function
func extractDLLsFromManifest(manifestPath string) ([]string, error) {
    dllInfos, err := extractDetailedDLLsFromManifest(manifestPath)
    if err != nil {
        return nil, err
    }
    
    // Extract just the DLL names/paths for backward compatibility
    dllNames := make([]string, len(dllInfos))
    for i, info := range dllInfos {
        if info.Path != "" {
            dllNames[i] = info.Path
        } else {
            dllNames[i] = info.Name
        }
    }
    
    return dllNames, nil
}

// Enhanced extraction with detailed DLL information
func extractDetailedDLLsFromManifest(manifestPath string) ([]DLLInfo, error) {
    var dlls []DLLInfo
    
    // Open manifest file
    file, err := os.Open(manifestPath)
    if err != nil {
        return nil, fmt.Errorf("failed to open manifest: %v", err)
    }
    defer file.Close()
    
    // Detect and handle UTF-16 encoding (common for Windows manifests)
    reader := detectAndDecodeEncoding(file)
    
    // Read and parse XML
    data, err := io.ReadAll(reader)
    if err != nil {
        return nil, fmt.Errorf("failed to read manifest: %v", err)
    }
    
    // Clean up the data (remove BOM if present)
    data = cleanXMLData(data)
    
    // Parse XML
    var assembly Assembly
    err = xml.Unmarshal(data, &assembly)
    if err != nil {
        // Try alternative parsing for malformed XML
        return parseManifestManually(data, manifestPath)
    }
    
    // Extract DLLs from file elements
    for _, file := range assembly.Files {
        if strings.HasSuffix(strings.ToLower(file.Name), ".dll") {
            dllInfo := DLLInfo{
                Name:          file.Name,
                Path:          filepath.Join(filepath.Dir(manifestPath), file.Name),
                Hash:          file.Hash,
                HashAlg:       file.Hashalg,
                SourceManifest: manifestPath,
            }
            
            // Extract associated COM classes
            for _, comClass := range file.COMClass {
                dllInfo.COMClasses = append(dllInfo.COMClasses, comClass.CLSID)
            }
            
            // Extract type libraries
            for _, typeLib := range file.TypeLibrary {
                dllInfo.TypeLibs = append(dllInfo.TypeLibs, typeLib.LIBID)
            }
            
            // Extract window classes
            for _, winClass := range file.WindowClass {
                dllInfo.WindowClasses = append(dllInfo.WindowClasses, winClass.ClassName)
            }
            
            dlls = append(dlls, dllInfo)
        }
    }
    
    // Extract CLR surrogate DLLs
    for _, clr := range assembly.ClrSurrogate {
        if clr.DllName != "" {
            dllInfo := DLLInfo{
                Name:           clr.DllName,
                Path:           filepath.Join(filepath.Dir(manifestPath), clr.DllName),
                IsClrSurrogate: true,
                SourceManifest: manifestPath,
            }
            
            if clr.CLSID != "" {
                dllInfo.COMClasses = append(dllInfo.COMClasses, clr.CLSID)
            }
            
            dlls = append(dlls, dllInfo)
        }
    }
    
    // Extract dependencies (referenced assemblies)
    for _, dep := range assembly.Dependency {
        if dep.DependentAssembly.AssemblyIdentity.Name != "" {
            // This is another assembly, not a direct DLL
            assemblyName := dep.DependentAssembly.AssemblyIdentity.Name
            if !strings.HasSuffix(strings.ToLower(assemblyName), ".dll") {
                assemblyName += ".dll"
            }
            
            dllInfo := DLLInfo{
                Name:          assemblyName,
                IsDependency:  true,
                SourceManifest: manifestPath,
            }
            
            // Try to find the actual DLL in WinSxS
            if winsxsPath := findInWinsxs(assemblyName, 
                dep.DependentAssembly.AssemblyIdentity.Version,
                dep.DependentAssembly.AssemblyIdentity.PublicKeyToken); winsxsPath != "" {
                dllInfo.Path = winsxsPath
            }
            
            dlls = append(dlls, dllInfo)
        }
    }
    
    // Also check for DLLs in WindowsSettings (some manifests have them there)
    if assembly.WindowsSettings != nil {
        // Check for printer drivers and other settings that might reference DLLs
        dlls = append(dlls, parseWindowsSettingsForDLLs(assembly.WindowsSettings, manifestPath)...)
        
        // Check for printer driver isolation DLLs
        if assembly.WindowsSettings.PrinterDriverIsolation != nil {
            printerDLLs := parsePrinterDriverIsolation(assembly.WindowsSettings.PrinterDriverIsolation, manifestPath)
            dlls = append(dlls, printerDLLs...)
        }
        
        // Check for DPI awareness settings that might reference DLLs
        if assembly.WindowsSettings.DpiAware != nil {
            if strings.Contains(strings.ToLower(assembly.WindowsSettings.DpiAware.Value), ".dll") {
                dllInfo := DLLInfo{
                    Name:          extractDLLNameFromString(assembly.WindowsSettings.DpiAware.Value),
                    Path:          filepath.Join(filepath.Dir(manifestPath), extractDLLNameFromString(assembly.WindowsSettings.DpiAware.Value)),
                    SourceManifest: manifestPath,
                }
                dlls = append(dlls, dllInfo)
            }
        }
        
        // Check for DPI awareness settings
        if assembly.WindowsSettings.DpiAwareness != nil {
            if strings.Contains(strings.ToLower(assembly.WindowsSettings.DpiAwareness.Value), ".dll") {
                dllInfo := DLLInfo{
                    Name:          extractDLLNameFromString(assembly.WindowsSettings.DpiAwareness.Value),
                    Path:          filepath.Join(filepath.Dir(manifestPath), extractDLLNameFromString(assembly.WindowsSettings.DpiAwareness.Value)),
                    SourceManifest: manifestPath,
                }
                dlls = append(dlls, dllInfo)
            }
        }
        
        // Check for auto-elevate settings
        if assembly.WindowsSettings.AutoElevate != nil {
            if strings.Contains(strings.ToLower(assembly.WindowsSettings.AutoElevate.Value), ".dll") {
                dllInfo := DLLInfo{
                    Name:          extractDLLNameFromString(assembly.WindowsSettings.AutoElevate.Value),
                    Path:          filepath.Join(filepath.Dir(manifestPath), extractDLLNameFromString(assembly.WindowsSettings.AutoElevate.Value)),
                    SourceManifest: manifestPath,
                }
                dlls = append(dlls, dllInfo)
            }
        }
        
        // Check for theming disable settings
        if assembly.WindowsSettings.DisableTheming != nil {
            if strings.Contains(strings.ToLower(assembly.WindowsSettings.DisableTheming.Value), ".dll") {
                dllInfo := DLLInfo{
                    Name:          extractDLLNameFromString(assembly.WindowsSettings.DisableTheming.Value),
                    Path:          filepath.Join(filepath.Dir(manifestPath), extractDLLNameFromString(assembly.WindowsSettings.DisableTheming.Value)),
                    SourceManifest: manifestPath,
                }
                dlls = append(dlls, dllInfo)
            }
        }
        
        // Check for window filtering settings
        if assembly.WindowsSettings.DisableWindowFiltering != nil {
            if strings.Contains(strings.ToLower(assembly.WindowsSettings.DisableWindowFiltering.Value), ".dll") {
                dllInfo := DLLInfo{
                    Name:          extractDLLNameFromString(assembly.WindowsSettings.DisableWindowFiltering.Value),
                    Path:          filepath.Join(filepath.Dir(manifestPath), extractDLLNameFromString(assembly.WindowsSettings.DisableWindowFiltering.Value)),
                    SourceManifest: manifestPath,
                }
                dlls = append(dlls, dllInfo)
            }
        }
        
        // Check for high resolution scrolling settings
        if assembly.WindowsSettings.HighResolutionScrolling != nil {
            if strings.Contains(strings.ToLower(assembly.WindowsSettings.HighResolutionScrolling.Value), ".dll") {
                dllInfo := DLLInfo{
                    Name:          extractDLLNameFromString(assembly.WindowsSettings.HighResolutionScrolling.Value),
                    Path:          filepath.Join(filepath.Dir(manifestPath), extractDLLNameFromString(assembly.WindowsSettings.HighResolutionScrolling.Value)),
                    SourceManifest: manifestPath,
                }
                dlls = append(dlls, dllInfo)
            }
        }
        
        // Check for ultra high resolution scrolling settings
        if assembly.WindowsSettings.UltraHighResolutionScrolling != nil {
            if strings.Contains(strings.ToLower(assembly.WindowsSettings.UltraHighResolutionScrolling.Value), ".dll") {
                dllInfo := DLLInfo{
                    Name:          extractDLLNameFromString(assembly.WindowsSettings.UltraHighResolutionScrolling.Value),
                    Path:          filepath.Join(filepath.Dir(manifestPath), extractDLLNameFromString(assembly.WindowsSettings.UltraHighResolutionScrolling.Value)),
                    SourceManifest: manifestPath,
                }
                dlls = append(dlls, dllInfo)
            }
        }
    }
    
    return dlls, nil
}

// parseWindowsSettingsForDLLs extracts DLL references from WindowsSettings structure
func parseWindowsSettingsForDLLs(settings *WindowsSettings, manifestPath string) []DLLInfo {
    var dlls []DLLInfo
    
    // Use reflection to iterate through all fields
    settingsValue := reflect.ValueOf(settings).Elem()
    settingsType := settingsValue.Type()
    
    for i := 0; i < settingsValue.NumField(); i++ {
        field := settingsValue.Field(i)
        fieldType := settingsType.Field(i)
        
        // Skip XMLName field
        if fieldType.Name == "XMLName" {
            continue
        }
        
        // Check if field is a pointer and not nil
        if field.Kind() == reflect.Ptr && !field.IsNil() {
            // Get the value of the pointer
            elem := field.Elem()
            
            // If it's a struct with a Value field
            if elem.Kind() == reflect.Struct {
                valueField := elem.FieldByName("Value")
                if valueField.IsValid() && valueField.Kind() == reflect.String {
                    valueStr := valueField.String()
                    if strings.Contains(strings.ToLower(valueStr), ".dll") {
                        dllName := extractDLLNameFromString(valueStr)
                        if dllName != "" {
                            dllInfo := DLLInfo{
                                Name:          dllName,
                                Path:          filepath.Join(filepath.Dir(manifestPath), dllName),
                                SourceManifest: manifestPath,
                            }
                            dlls = append(dlls, dllInfo)
                        }
                    }
                }
            }
        }
    }
    
    return dlls
}

// parsePrinterDriverIsolation extracts DLL references from printer driver isolation settings
func parsePrinterDriverIsolation(isolation *PrinterDriverIsolation, manifestPath string) []DLLInfo {
    var dlls []DLLInfo
    
    if isolation == nil {
        return dlls
    }
    
    // Printer driver isolation often contains references to printer driver DLLs
    // Common printer driver DLL patterns
    value := isolation.Value
    
    // Check for common printer driver DLL patterns
    patterns := []string{
        `unidrv\.dll`,
        `p5ins\.dll`,
        `pscript\.dll`,
        `rasdd\.dll`,
        `truetype\.dll`,
        `mxdwdrv\.dll`,
        `pdfmon\.dll`,
        `xpsdrv\.dll`,
        `*\.dll`,
    }
    
    for _, pattern := range patterns {
        if strings.Contains(strings.ToLower(value), strings.TrimSuffix(pattern, "*.")) {
            re := regexp.MustCompile(`([a-zA-Z0-9_\-]+\.dll)`)
            matches := re.FindAllStringSubmatch(value, -1)
            for _, match := range matches {
                if len(match) >= 2 {
                    dllInfo := DLLInfo{
                        Name:          match[1],
                        Path:          filepath.Join(filepath.Dir(manifestPath), match[1]),
                        SourceManifest: manifestPath,
                    }
                    dlls = append(dlls, dllInfo)
                }
            }
        }
    }
    
    // Also check for XML-structured printer driver info
    if strings.Contains(value, "<") && strings.Contains(value, ">") {
        // Try to parse as XML
        var printerConfig struct {
            DriverName string `xml:"driverName,attr"`
            DriverDLL  string `xml:"driverDLL,attr"`
            ConfigDLL  string `xml:"configDLL,attr"`
            DataDLL    string `xml:"dataDLL,attr"`
            HelpDLL    string `xml:"helpDLL,attr"`
        }
        
        err := xml.Unmarshal([]byte(value), &printerConfig)
        if err == nil {
            if printerConfig.DriverDLL != "" && strings.HasSuffix(strings.ToLower(printerConfig.DriverDLL), ".dll") {
                dllInfo := DLLInfo{
                    Name:          printerConfig.DriverDLL,
                    Path:          filepath.Join(filepath.Dir(manifestPath), printerConfig.DriverDLL),
                    SourceManifest: manifestPath,
                }
                dlls = append(dlls, dllInfo)
            }
            if printerConfig.ConfigDLL != "" && strings.HasSuffix(strings.ToLower(printerConfig.ConfigDLL), ".dll") {
                dllInfo := DLLInfo{
                    Name:          printerConfig.ConfigDLL,
                    Path:          filepath.Join(filepath.Dir(manifestPath), printerConfig.ConfigDLL),
                    SourceManifest: manifestPath,
                }
                dlls = append(dlls, dllInfo)
            }
            if printerConfig.DataDLL != "" && strings.HasSuffix(strings.ToLower(printerConfig.DataDLL), ".dll") {
                dllInfo := DLLInfo{
                    Name:          printerConfig.DataDLL,
                    Path:          filepath.Join(filepath.Dir(manifestPath), printerConfig.DataDLL),
                    SourceManifest: manifestPath,
                }
                dlls = append(dlls, dllInfo)
            }
            if printerConfig.HelpDLL != "" && strings.HasSuffix(strings.ToLower(printerConfig.HelpDLL), ".dll") {
                dllInfo := DLLInfo{
                    Name:          printerConfig.HelpDLL,
                    Path:          filepath.Join(filepath.Dir(manifestPath), printerConfig.HelpDLL),
                    SourceManifest: manifestPath,
                }
                dlls = append(dlls, dllInfo)
            }
        }
    }
    
    return dlls
}

// extractDLLNameFromString extracts DLL name from a string that might contain paths or XML
func extractDLLNameFromString(input string) string {
    // Look for DLL pattern
    re := regexp.MustCompile(`([a-zA-Z0-9_\-]+\.dll)`)
    matches := re.FindStringSubmatch(input)
    if len(matches) >= 2 {
        return matches[1]
    }
    
    // If no match, check if the whole string looks like a DLL
    if strings.HasSuffix(strings.ToLower(input), ".dll") {
        return input
    }
    
    return ""
}


// Detect file encoding (UTF-8, UTF-16 LE/BE)
func detectAndDecodeEncoding(r io.Reader) io.Reader {
    // Read first few bytes to detect BOM
    peekReader := &peekableReader{reader: r}
    bom, err := peekReader.Peek(4)
    if err != nil {
        return peekReader
    }
    
    // Check for UTF-16 LE BOM (0xFF 0xFE)
    if len(bom) >= 2 && bom[0] == 0xFF && bom[1] == 0xFE {
        return transform.NewReader(peekReader, unicode.UTF16(unicode.LittleEndian, unicode.UseBOM).NewDecoder())
    }
    
    // Check for UTF-16 BE BOM (0xFE 0xFF)
    if len(bom) >= 2 && bom[0] == 0xFE && bom[1] == 0xFF {
        return transform.NewReader(peekReader, unicode.UTF16(unicode.BigEndian, unicode.UseBOM).NewDecoder())
    }
    
    // Check for UTF-8 BOM (0xEF 0xBB 0xBF)
    if len(bom) >= 3 && bom[0] == 0xEF && bom[1] == 0xBB && bom[2] == 0xBF {
        // Skip BOM
        peekReader.Read(make([]byte, 3))
        return peekReader
    }
    
    return peekReader
}

// Peekable reader implementation
type peekableReader struct {
    reader io.Reader
    buffer []byte
}

func (r *peekableReader) Read(p []byte) (n int, err error) {
    if len(r.buffer) > 0 {
        n = copy(p, r.buffer)
        r.buffer = r.buffer[n:]
        if len(r.buffer) > 0 {
            return n, nil
        }
    }
    
    var extraN int
    extraN, err = r.reader.Read(p[n:])
    return n + extraN, err
}

func (r *peekableReader) Peek(n int) ([]byte, error) {
    if len(r.buffer) >= n {
        return r.buffer[:n], nil
    }
    
    // Need to read more
    need := n - len(r.buffer)
    temp := make([]byte, need)
    read, err := r.reader.Read(temp)
    if err != nil {
        return nil, err
    }
    
    r.buffer = append(r.buffer, temp[:read]...)
    
    if len(r.buffer) < n {
        return r.buffer, io.EOF
    }
    
    return r.buffer[:n], nil
}

// Clean XML data (remove invalid characters, etc.)
func cleanXMLData(data []byte) []byte {
    // Remove any non-printable characters that might break XML parsing
    result := make([]byte, 0, len(data))
    for _, b := range data {
        if b >= 0x20 || b == '\t' || b == '\n' || b == '\r' {
            result = append(result, b)
        }
    }
    return result
}

// Manual parsing fallback for malformed manifests
func parseManifestManually(data []byte, manifestPath string) ([]DLLInfo, error) {
    var dlls []DLLInfo
    content := string(data)
    
    // Look for various patterns using proper regex
    patterns := []string{
        `name="([^"]+\.dll)"`,
        `file name="([^"]+\.dll)"`,
        `dll="([^"]+\.dll)"`,
        `imageLocation="([^"]+\.dll)"`,
        `<file[^>]*name="([^"]+\.dll)"`,
        `dllName="([^"]+\.dll)"`,
        `clrSurrogate[^>]*dllName="([^"]+\.dll)"`,
    }
    
    for _, pattern := range patterns {
        re := regexp.MustCompile(pattern)
        matches := re.FindAllStringSubmatch(content, -1)
        for _, match := range matches {
            if len(match) >= 2 {
                dllName := match[1]
                dllInfo := DLLInfo{
                    Name:          dllName,
                    Path:          filepath.Join(filepath.Dir(manifestPath), dllName),
                    SourceManifest: manifestPath,
                }
                dlls = append(dlls, dllInfo)
            }
        }
    }
    
    // Also look for CDATA sections that might contain DLL names
    cdataRe := regexp.MustCompile(`<!\[CDATA\[(.*?)\]\]>`)
    cdataMatches := cdataRe.FindAllStringSubmatch(content, -1)
    for _, match := range cdataMatches {
        if len(match) >= 2 {
            cdata := match[1]
            if strings.Contains(cdata, ".dll") {
                // Extract DLL names from CDATA
                words := strings.FieldsFunc(cdata, func(r rune) bool {
                    return !unicode.IsLetter(r) && !unicode.IsNumber(r) && 
                           r != '.' && r != '\\' && r != '/'
                })
                for _, word := range words {
                    if strings.HasSuffix(strings.ToLower(word), ".dll") {
                        dllInfo := DLLInfo{
                            Name:          word,
                            Path:          filepath.Join(filepath.Dir(manifestPath), word),
                            SourceManifest: manifestPath,
                        }
                        dlls = append(dlls, dllInfo)
                    }
                }
            }
        }
    }
    
    if len(dlls) == 0 {
        return nil, fmt.Errorf("no DLLs found in manifest using manual parsing")
    }
    
    return dlls, nil
}

// Find a DLL in WinSxS by name, version, and public key token
func findInWinsxs(dllName, version, publicKeyToken string) string {
    if dllName == "" {
        return ""
    }
    
    winsxsBase := "C:\\Windows\\WinSxS"
    
    // Search patterns for WinSxS
    patterns := []string{
        filepath.Join(winsxsBase, "*", dllName),
        filepath.Join(winsxsBase, "amd64_*", dllName),
        filepath.Join(winsxsBase, "x86_*", dllName),
        filepath.Join(winsxsBase, "wow64_*", dllName),
        filepath.Join(winsxsBase, "msil_*", dllName),
    }
    
    if version != "" {
        patterns = append(patterns, 
            filepath.Join(winsxsBase, fmt.Sprintf("*%s*", version), dllName))
    }
    
    if publicKeyToken != "" {
        patterns = append(patterns, 
            filepath.Join(winsxsBase, fmt.Sprintf("*%s*", publicKeyToken), dllName))
    }
    
    for _, pattern := range patterns {
        matches, err := filepath.Glob(pattern)
        if err == nil && len(matches) > 0 {
            return matches[0]
        }
    }
    
    return ""
}

// Batch processing for multiple manifests
func extractDLLsFromManifests(manifestPaths []string) (map[string][]DLLInfo, error) {
    results := make(map[string][]DLLInfo)
    
    for _, path := range manifestPaths {
        dlls, err := extractDetailedDLLsFromManifest(path)
        if err != nil {
            fmt.Printf("[!] Warning: Failed to parse %s: %v\n", path, err)
            continue
        }
        
        if len(dlls) > 0 {
            results[path] = dlls
        }
    }
    
    return results, nil
}

// Verify DLL existence and permissions
func verifyDLLs(dlls []DLLInfo) []DLLInfo {
    var verified []DLLInfo
    
    for _, dll := range dlls {
        // Check multiple possible paths
        pathsToCheck := []string{
            dll.Path,
            filepath.Join("C:\\Windows\\System32", dll.Name),
            filepath.Join("C:\\Windows\\SysWOW64", dll.Name),
            filepath.Join("C:\\Windows", dll.Name),
        }
        
        for _, path := range pathsToCheck {
            if info, err := os.Stat(path); err == nil && !info.IsDir() {
                dll.Path = path
                dll.Verified = true
                break
            }
        }
        
        verified = append(verified, dll)
    }
    
    return verified
}
