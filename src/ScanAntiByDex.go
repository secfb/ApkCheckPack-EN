package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"path"
)

// Common detection pattern structure
type DetectionPattern struct {
    Pattern     string
    Description string
}

// Root file path detection patterns
var RootFilePatterns = []DetectionPattern{
    {Pattern: "/cache/.disable_magisk", Description: "Magisk disable flag file"},
    {Pattern: "/cache/magisk.log", Description: "Magisk log file"},
    {Pattern: "/cache/su", Description: "SuperSU leftover file"},
    {Pattern: "/data/adb/ksu", Description: "KernelSU install directory"},
    {Pattern: "/data/adb/ksud", Description: "KernelSU daemon"},
    {Pattern: "/data/adb/magisk", Description: "Magisk main directory"},
    {Pattern: "/data/adb/magisk.db", Description: "Magisk policy database"},
    {Pattern: "/data/adb/magisk.img", Description: "Magisk image file"},
    {Pattern: "/data/adb/magisk_simple", Description: "Magisk simple mode marker"},
    {Pattern: "/data/local/bin/su", Description: "Common SU binary path"},
    {Pattern: "/data/local/su", Description: "Alternate SU binary path"},
    {Pattern: "/data/local/xbin/su", Description: "Xposed framework SU path"},
    {Pattern: "/data/su", Description: "SU configuration directory"},
    {Pattern: "/dev/.magisk.unblock", Description: "Magisk unlock marker"},
    {Pattern: "/dev/com.koushikdutta.superuser.daemon/", Description: "Superuser daemon socket"},
    {Pattern: "/dev/su", Description: "SU device node"},
    {Pattern: "/init.magisk.rc", Description: "Magisk init script"},
    {Pattern: "/sbin/.magisk", Description: "Magisk temp directory"},
    {Pattern: "/sbin/su", Description: "System partition SU file"},
    {Pattern: "/su/bin/su", Description: "Systemless SU path"},
    {Pattern: "/system/app/Kinguser.apk", Description: "Kingroot APK"},
    {Pattern: "/system/app/Superuser.apk", Description: "Superuser APK"},
    {Pattern: "/system/bin/.ext/su", Description: "Hidden SU file"},
    {Pattern: "/system/bin/failsafe/su", Description: "Failsafe SU"},
    {Pattern: "/system/bin/su", Description: "System built-in SU"},
    {Pattern: "/system/etc/init.d/99SuperSUDaemon", Description: "SuperSU daemon script"},
    {Pattern: "/system/sbin/su", Description: "Alternate system partition SU path"},
    {Pattern: "/system/sd/xbin/su", Description: "SD card extended SU path"},
    {Pattern: "/system/usr/we-need-root/su", Description: "Special directory SU file"},
    {Pattern: "/system/xbin/busybox", Description: "BusyBox tool (often root-related)"},
    {Pattern: "/system/xbin/daemonsu", Description: "SuperSU daemon"},
    {Pattern: "/system/xbin/ku.sud", Description: "Kinguser daemon"},
    {Pattern: "/system/xbin/su", Description: "Common SU path"},
    {Pattern: "/vendor/bin/su", Description: "Vendor partition SU file"},
    {Pattern: "Kinguser.apk", Description: "Kingroot APK (partial match)"},
    {Pattern: "Superuser.apk", Description: "Superuser APK (partial match)"},
    {Pattern: "/system/xbin/", Description: "Common root tools directory (partial match)"},
    {Pattern: "/vendor/bin/", Description: "Vendor root tools directory (partial match)"},
}

// Root management app package name patterns
var RootAppPatterns = []DetectionPattern{
    {Pattern: "com.chelpus.lackypatch", Description: "Lucky Patcher tool"},
    {Pattern: "com.dimonvideo.luckypatcher", Description: "Lucky Patcher official package"},
    {Pattern: "com.koushikdutta.rommanager", Description: "Rom Manager flashing tool"},
    {Pattern: "com.koushikdutta.rommanager.license", Description: "Rom Manager license"},
    {Pattern: "com.koushikdutta.superuser", Description: "Koush's Superuser"},
    {Pattern: "com.noshufou.android.su", Description: "Superuser official package"},
    {Pattern: "com.noshufou.android.su.elite", Description: "Superuser paid version"},
    {Pattern: "com.ramdroid.appquarantine", Description: "App quarantine tool (requires root)"},
    {Pattern: "com.ramdroid.appquarantinepro", Description: "Pro app quarantine"},
    {Pattern: "com.thirdparty.superuser", Description: "Third-party Superuser app"},
    {Pattern: "com.topjohnwu.magisk", Description: "Magisk Manager"},
    {Pattern: "com.yellowes.su", Description: "Early SuperSU variant"},
    {Pattern: "eu.chainfire.supersu", Description: "Chainfire SuperSU"},
    {Pattern: "me.weishu.kernelsu", Description: "KernelSU manager"},
    {Pattern: "com.kingroot.kinguser", Description: "KingRoot main app"},
    {Pattern: "com.kingoapp.root", Description: "KingoRoot"},
    {Pattern: "me.phh.superuser", Description: "PHH's Superuser"},
    {Pattern: "com.apusapps.browser.module.root", Description: "Browser-based root tool"},
    {Pattern: "io.github.vvb2060.magisk", Description: "Magisk derivative"},
    {Pattern: "com.topjohnwu.magisk.pro", Description: "Magisk Pro"},
    {Pattern: "de.robv.android.xposed.installer", Description: "Xposed installer"},
    {Pattern: "org.meowcat.edxposed.manager", Description: "EdXposed manager"},
    {Pattern: "me.weishu.exp", Description: "Taichi framework"},
    {Pattern: "com.speedsoftware.rootexplorer", Description: "Root Explorer"},
    {Pattern: "com.keramidas.TitaniumBackup", Description: "Titanium Backup"},
    {Pattern: "com.joeykrim.rootcheck", Description: "Root checker tool"},
    {Pattern: "com.device.report", Description: "Root reporting tool"},
    {Pattern: "com.qihoo.root", Description: "360 Root"},
    {Pattern: "com.dianxinos.optimizer.duplay", Description: "Dianxin Root"},
    {Pattern: "com.geohot.towelroot", Description: "Towelroot exploit"},
    {Pattern: "com.zachspong.temprootremove", Description: "Temporary root tool"},
    {Pattern: "com.riru.core", Description: "Riru core module"},
    {Pattern: "com.github.topjohnwu.magisk.installer", Description: "Magisk installer"},
    {Pattern: "com.alephzain.framaroot", Description: "Framaroot tool"},
    {Pattern: "org.chainfire.internet", Description: "Chainfire network tool"},
}

// Emulator detection patterns
var EmulatorPatterns = []DetectionPattern{
    {Pattern: "tel:123456", Description: "Default emulator phone number"},
    {Pattern: "test-keys", Description: "Test-keys system"},
    {Pattern: "goldfish", Description: "Android emulator kernel identifier"},
    {Pattern: "android-test", Description: "Test environment identifier"},
    {Pattern: "000000000000000", Description: "Default emulator IMEI"},
    {Pattern: "/dev/socket/qemud", Description: "QEMU daemon socket"},
    {Pattern: "/dev/qemu_pipe", Description: "QEMU pipe interface"},
    {Pattern: "/dev/qemu_trace", Description: "QEMU trace interface"},
    {Pattern: "ro.kernel.qemu", Description: "QEMU kernel property"},
    {Pattern: "generic_x86", Description: "Common emulator ABI"},
    {Pattern: "emulator", Description: "Emulator indicator"},
    {Pattern: "ro.boot.virtual", Description: "Virtual boot indicator"},
    {Pattern: "ro.cloudbuild.software", Description: "Cloud build indicator"},
    {Pattern: "ro.secureboot.lockstate", Description: "Secure boot lock state anomaly"},
    {Pattern: "ro.cpu.virtual", Description: "Virtual CPU indicator"},
    {Pattern: "Build.PRODUCT=sdk_google", Description: "SDK build identifier"},
    {Pattern: "Build.MODEL=Android SDK built", Description: "SDK build model"},
    {Pattern: "Build.HARDWARE=goldfish", Description: "Emulator hardware identifier"},
    {Pattern: "Build.FINGERPRINT=generic", Description: "Generic fingerprint"},
    {Pattern: "Sensor.TYPE_SIGNIFICANT_MOTION", Description: "Real-device-specific sensor check"},
    {Pattern: "Sensor.TYPE_STEP_COUNTER", Description: "Step counter sensor check"},
    {Pattern: "Sensor.TYPE_HEART_RATE", Description: "Heart rate sensor check"},
    {Pattern: "10.0.2.15", Description: "Default NAT gateway IP"},
    {Pattern: "eth0", Description: "Emulator network interface"},
    {Pattern: "dns.google", Description: "Emulator default DNS"},
    {Pattern: "debug.stagefright.ccode", Description: "Stagefright framework feature"},
    {Pattern: "ro.kernel.android.checkjni", Description: "JNI check mode"},
    {Pattern: "ro.boot.selinux=disabled", Description: "SELinux disabled state"},
    {Pattern: "hasQemuSocket", Description: "QEMU socket check function"},
    {Pattern: "hasQemuPipe", Description: "QEMU pipe check function"},
    {Pattern: "getEmulatorQEMUKernel", Description: "QEMU kernel property check function"},
    {Pattern: "Landroid/os/SystemProperties;->get(Ljava/lang/String;)", Description: "System property access pattern"},
}

// Anti-debug detection patterns
var DebugPatterns = []DetectionPattern{
    {Pattern: "checkFridaRunningProcesses", Description: "Frida process detection"},
    {Pattern: "checkRunningProcesses", Description: "Detect frida-server process"},
    {Pattern: "checkRunningServices", Description: "Detect supersu/superuser service"},
    {Pattern: "treadCpuTimeNanos", Description: "CPU time delta debug check"},
    {Pattern: "TamperingWithJavaRuntime", Description: "Java runtime tampering detection"},
    {Pattern: "com.android.internal.os.ZygoteInit", Description: "Zygote init detection"},
    {Pattern: "com.saurik.substrate.MS$2", Description: "Substrate framework detection"},
    {Pattern: "de.robv.android.xposed.XposedBridge", Description: "Xposed framework detection"},
    {Pattern: "detectBypassSSL", Description: "SSL certificate bypass detection"},
    {Pattern: "Landroid/os/Debug;->isDebuggerConnected()Z", Description: "Debugger connection detection"},
    {Pattern: ":27042", Description: "Frida default port detection"},
    {Pattern: ":23946", Description: "ADB debug port detection"},
    {Pattern: "frida-gadget", Description: "Frida tool detection"},
    {Pattern: "libfrida.so", Description: "Frida library detection"},
    {Pattern: "XposedBridge.jar", Description: "Xposed bridge file detection"},
    {Pattern: "EdXposed", Description: "EdXposed framework detection"},
    {Pattern: "frida-server", Description: "Frida server process detection"},
    {Pattern: "android_server", Description: "IDA debug server detection"},
    {Pattern: "gdbserver", Description: "GDB debug server detection"},
    {Pattern: "ro.debuggable", Description: "System debug property detection"},
    {Pattern: "service.adb.root", Description: "ADB root service detection"},
    {Pattern: "XposedInstaller", Description: "Xposed installer detection"},
    {Pattern: "Magisk", Description: "Magisk framework detection"},
    {Pattern: "LSPosed", Description: "LSPosed framework detection"},
    {Pattern: "ptrace", Description: "Ptrace debug detection"},
    {Pattern: "/proc/self/status", Description: "TracerPid status detection"},
    {Pattern: "libsubstrate.so", Description: "Substrate library detection"},
    {Pattern: "com.saurik.substrate", Description: "Substrate framework detection"},
    {Pattern: "sslunpinning", Description: "SSL unpinning detection"},
    {Pattern: "JustTrustMe", Description: "SSL certificate bypass module detection"},
    {Pattern: "/data/data/de.robv.android.xposed.installer/conf/modules.list", Description: "Xposed modules list detection"},
}

// Proxy detection pattern list
var ProxyPatterns = []DetectionPattern{
    {Pattern: "Lokhttp3/Proxy;->NO_PROXY:Lokhttp3/Proxy;", Description: "OkHttp explicitly disables proxy"},
    {Pattern: "Lokhttp3/OkHttpClient$Builder;->proxy(Lokhttp3/Proxy;)Lokhttp3/OkHttpClient$Builder;", Description: "OkHttp proxy configuration call"},
    {Pattern: "Lokhttp3/internal/proxy/NullProxySelector;", Description: "OkHttp null proxy selector"},
    {Pattern: "Ljava/lang/System;->getProperty(Ljava/lang/String;)Ljava/lang/String;", Description: "System proxy properties access"},
    {Pattern: "Landroid/net/Proxy;->getDefaultProxy()Landroid/net/Proxy;", Description: "Get default proxy"},
    {Pattern: "Landroid/net/Proxy;->getHost()Ljava/lang/String;", Description: "Get proxy host"},
    {Pattern: "Landroid/net/Proxy;->getPort()I", Description: "Get proxy port"},
    {Pattern: "Landroid/net/ConnectivityManager;->getActiveNetworkInfo", Description: "Get active network info"},
    {Pattern: "Landroid/net/NetworkInfo;->getType", Description: "Get network type"},
    {Pattern: "Ljavax/net/ssl/X509TrustManager;", Description: "Custom certificate trust manager"},
    {Pattern: "Ljavax/net/ssl/SSLContext;->init", Description: "Initialize SSL context"},
    {Pattern: "VPNService", Description: "VPN service detection"},
    {Pattern: "NetworkCapabilities.TRANSPORT_VPN", Description: "VPN transport capability detection"},
    {Pattern: "isVpnUsed", Description: "VPN usage detection"},
}

func ScanDexAnti(dexData []byte, filePath string) {
	// Control ROOT detection via flags
	if *ArgCheckRoot {
		// Check root file paths
		for _, pattern := range RootFilePatterns {
			if bytes.Contains(dexData, []byte(pattern.Pattern)) {
				result := fmt.Sprintf("    %s -> %s (%s)", 
					filePath, pattern.Pattern, pattern.Description)
				allRootResults = append(allRootResults, result)
			}
		}
		// Check root app package names
		for _, pattern := range RootAppPatterns {
			if bytes.Contains(dexData, []byte(pattern.Pattern)) {
				result := fmt.Sprintf("    %s -> %s (%s)", 
					filePath, pattern.Pattern, pattern.Description)
				allRootResults = append(allRootResults, result)
			}
		}
	}

	// Control emulator detection via flags
	if *ArgCheckEmu {
		for _, pattern := range EmulatorPatterns {
			if bytes.Contains(dexData, []byte(pattern.Pattern)) {
				result := fmt.Sprintf("    %s -> %s (%s)", 
					filePath, pattern.Pattern, pattern.Description)
				allEmuResults = append(allEmuResults, result)
			}
		}
	}

	// Control anti-debug detection via flags
	if *ArgCheckDebug {
		for _, pattern := range DebugPatterns {
			if bytes.Contains(dexData, []byte(pattern.Pattern)) {
				result := fmt.Sprintf("    %s -> %s (%s)", 
					filePath, pattern.Pattern, pattern.Description)
				allDebugResults = append(allDebugResults, result)
			}
		}
	}

	// Control proxy detection via flags
	if *ArgCheckProxy {
		for _, pattern := range ProxyPatterns {
			if bytes.Contains(dexData, []byte(pattern.Pattern)) {
				result := fmt.Sprintf("    %s -> %s (%s)", 
					filePath, pattern.Pattern, pattern.Description)
				allProxyResults = append(allProxyResults, result)
			}
		}
	}
}

// Global variables to collect detection results from all DEX files
var (
    allRootResults  []string
    allEmuResults   []string
    allDebugResults []string
    allProxyResults []string
)

// Clear all detection results
func clearAntiResults() {
    allRootResults = []string{}
    allEmuResults = []string{}
    allDebugResults = []string{}
    allProxyResults = []string{}
}

func ScanAPKAnti(apkReader *zip.Reader) bool {
    // Clear previous detection results
    clearAntiResults()
    
    // Read and scan DEX files
    for _, file := range apkReader.File {
        if path.Ext(file.Name) == ".dex" {
            fileReader, err := file.Open()
            if err != nil {
                fmt.Println(err)
                continue
            }
            
            // Use max size parameter from main package
            maxSize := int64(300 * 1024 * 1024) // default 300MB
            dexData, err := io.ReadAll(io.LimitReader(fileReader, maxSize))
            fileReader.Close()
            if err != nil {
                fmt.Println(err)
                continue
            }
            
            ScanDexAnti(dexData, file.Name)
        }
    }
    
    // Output results
    fmt.Println("\n===================== Security Detection Pattern Scan Results =====================")
    
    if *ArgCheckRoot && len(allRootResults) > 0 {
        fmt.Println("\n[ROOT Detection Patterns]")
        for _, result := range allRootResults {
            fmt.Println(result)
        }
    }

    if *ArgCheckEmu && len(allEmuResults) > 0 {
        fmt.Println("\n[Emulator Detection Patterns]")
        for _, result := range allEmuResults {
            fmt.Println(result)
        }
    }

    if *ArgCheckDebug && len(allDebugResults) > 0 {
        fmt.Println("\n[Anti-Debug Detection Patterns]")
        for _, result := range allDebugResults {
            fmt.Println(result)
        }
    }

    if *ArgCheckProxy && len(allProxyResults) > 0 {
        fmt.Println("\n[Proxy Detection Patterns]")
        for _, result := range allProxyResults {
            fmt.Println(result)
        }
    }
    
    // fmt.Println("\n================================================================")

    return true
}
