package com.example.engine

import android.content.Context
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.hardware.display.DisplayManager
import android.os.Build
import android.os.Environment
import android.view.Display
import com.example.model.EnvironmentSnapshot
import java.io.File

data class BaselineProbeResult(
    val environment: EnvironmentSnapshot,
    val getpropAll: String,
    val dumpsysFingerprint: String,
    val dumpsysBiometric: String,
    val dumpsysSurfaceFlinger: String,
    val dumpsysDisplay: String,
    val dumpsysOverlay: String,
    val lshalOutput: String,
    val vintfManifests: String,
    val serviceList: String,
    val sysfsFodNodes: String,
    val selinuxDenials: String,
    val initRcSnippets: String,
    val discoveredBinaryPaths: List<String>,
    val logcatBaseline: String,
    val installedOverlayPackages: List<String>
)

class SystemProbeCollector(private val context: Context) {

    suspend fun collectBaseline(useRoot: Boolean): BaselineProbeResult {
        val accessLimitations = mutableListOf<String>()
        var rootGranted = false

        if (useRoot) {
            val (ok, detail) = ShellExecutor.testRootAccess()
            rootGranted = ok
            if (!ok) {
                accessLimitations += "Root requested but denied/unavailable ($detail). Falling back to unprivileged probes."
            }
        } else {
            accessLimitations += "Root mode disabled in Settings: dumpsys, lshal, cmd overlay, vendor ELF binaries, full sysfs, and init.rc require root (su) or ADB DUMP privilege."
        }

        val effectiveRoot = useRoot && rootGranted

        val getpropRes = ShellExecutor.exec("getprop", useRoot = false)
        val getpropAll = getpropRes.stdout
        if (!getpropRes.isSuccess) {
            accessLimitations += "getprop returned exit=${getpropRes.exitCode}: ${getpropRes.stderr.trim()}"
        }

        val propMap = parseProperties(getpropAll)
        val gsiIndicators = detectGsiIndicators(propMap)

        // Privileged Binder / HAL / Overlay dumps require root (su) from inside an app process.
        // Calling dumpsys/lshal/cmd/service list without root triggers Binder/Parcel NULL-string and refPid errors.
        val dumpsysFp: String
        val dumpsysBio: String
        val dumpsysSf: String
        val dumpsysDisp: String
        val dumpsysOverlay: String
        val lshalRes: String
        val serviceListRes: String

        if (effectiveRoot) {
            dumpsysFp = probeCommand("dumpsys fingerprint", true, accessLimitations)
            dumpsysBio = probeCommand("dumpsys biometric", true, accessLimitations)
            dumpsysSf = probeCommand("dumpsys SurfaceFlinger", true, accessLimitations)
            dumpsysDisp = probeCommand("dumpsys display", true, accessLimitations)
            dumpsysOverlay = probeCommand("cmd overlay list", true, accessLimitations)
                .ifBlank { probeCommand("dumpsys overlay", true, accessLimitations) }
            // -i --neat lists HAL interfaces without parsing /proc/<pid>/maps refPids
            lshalRes = probeCommand("lshal -i --neat", true, accessLimitations)
            serviceListRes = probeCommand("service list", true, accessLimitations)
        } else {
            dumpsysFp = ""
            dumpsysBio = ""
            dumpsysSf = ""
            dumpsysDisp = ""
            dumpsysOverlay = ""
            lshalRes = ""
            serviceListRes = ""
            accessLimitations += "Privileged diagnostics skipped in non-root mode (dumpsys fingerprint/biometric/SurfaceFlinger/display, cmd overlay, lshal, service list)."
        }

        val vintfRes = if (effectiveRoot) {
            probeCommand(
                "cat /vendor/etc/vintf/manifest.xml /vendor/etc/vintf/manifest/*.xml /system/etc/vintf/manifest.xml 2>/dev/null",
                true,
                accessLimitations
            )
        } else {
            readReadableVintfFiles(accessLimitations)
        }

        val sysfsRes = if (effectiveRoot) {
            probeCommand(
                "for p in /sys/class/drm/*/hbm* /sys/class/drm/*/fod* /sys/class/drm/*/lhbm* /sys/class/drm/*/dim* /sys/class/backlight/*/*brightness* /sys/devices/platform/*/fod* /sys/devices/platform/*/udfps* /sys/devices/virtual/touch/touch_dev/fod* /sys/kernel/oppo_display/* /sys/kernel/oplus_display/*; do if [ -e \"\$p\" ]; then echo \"=== \$p ===\"; cat \"\$p\" 2>&1; fi; done",
                true,
                accessLimitations
            )
        } else {
            readReadableSysfsNodes(accessLimitations)
        }

        val selinuxModeRes = ShellExecutor.exec("getenforce", useRoot = false)
        val selinuxMode = selinuxModeRes.stdout.trim().ifBlank {
            propMap["ro.boot.selinux"] ?: "UNKNOWN"
        }

        val avcRes = if (effectiveRoot) {
            probeCommand(
                "logcat -d -b all -t 600 | grep -iE 'avc:|fod|udfps|fingerprint|biometric|hbm|lhbm' | tail -n 300",
                true,
                accessLimitations
            )
        } else {
            probeCommand(
                "logcat -d -t 400 | grep -iE 'avc:|fod|udfps|fingerprint|biometric|hbm|lhbm'",
                false,
                accessLimitations
            )
        }

        val initRcRes = if (effectiveRoot) {
            probeCommand(
                "grep -rnE 'fingerprint|fod|udfps|hbm|lhbm|goodix|fpc|silead|focal|egis|synaptics' /vendor/etc/init /system/etc/init /system_ext/etc/init /product/etc/init 2>/dev/null | head -n 200",
                true,
                accessLimitations
            )
        } else {
            readReadableInitRcSnippets(accessLimitations)
        }

        val discoveredBinaries = if (effectiveRoot) {
            val binaryListing = probeCommand(
                "ls -1 /vendor/bin/hw/*fingerprint* /vendor/bin/hw/*biometric* /vendor/bin/hw/*fod* /vendor/lib64/hw/*fingerprint* /vendor/lib64/*fod* /vendor/lib64/*goodix* /vendor/lib64/*fpc* /vendor/lib64/*silead* /vendor/lib64/*focal* /vendor/lib64/*egis* /system/lib64/*fingerprint* /system_ext/lib64/*fod* 2>/dev/null",
                true,
                accessLimitations
            )
            binaryListing.lines()
                .map { it.trim() }
                .filter { it.startsWith("/") && !it.contains("No such file") && !it.contains("Permission denied") }
                .distinct()
        } else {
            scanReadableBinaries(accessLimitations)
        }

        val logcatBase = probeCommand(
            "logcat -d -t 400 | grep -iE 'fingerprint|biometric|udfps|fod|hbm|lhbm|SurfaceFlinger|DisplayPower|Keyguard'",
            effectiveRoot,
            accessLimitations
        )

        val bioStatus = queryBiometricHardwareStatus()
        val displaySummary = queryDisplayModesSummary()
        val overlayPackages = queryInstalledFodOverlays()

        val bootSig = listOfNotNull(
            propMap["ro.bootimage.build.fingerprint"],
            propMap["ro.boot.vbmeta.digest"],
            propMap["ro.build.kernel.id"],
            ShellExecutor.exec("uname -r", false).stdout.trim().takeIf { it.isNotBlank() }
        ).joinToString(" | ").ifBlank { "UNKNOWN (inaccessible via props/uname)" }

        val vendorFp = propMap["ro.vendor.build.fingerprint"]
            ?: propMap["ro.odm.build.fingerprint"]
            ?: "UNKNOWN"

        val storageAllFiles = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Environment.isExternalStorageManager()
        } else {
            true
        }

        val env = EnvironmentSnapshot(
            deviceModel = "${Build.MANUFACTURER} ${Build.MODEL}",
            manufacturer = Build.MANUFACTURER,
            board = Build.BOARD,
            hardware = Build.HARDWARE,
            androidRelease = Build.VERSION.RELEASE ?: "?",
            sdkInt = Build.VERSION.SDK_INT,
            buildFingerprint = Build.FINGERPRINT,
            buildType = Build.TYPE,
            isGsiSuspected = gsiIndicators.isNotEmpty(),
            gsiIndicators = gsiIndicators,
            bootSignature = bootSig,
            vendorFingerprint = vendorFp,
            selinuxMode = selinuxMode,
            rootRequested = useRoot,
            rootGranted = rootGranted,
            storageAllFilesGranted = storageAllFiles,
            biometricHardwareStatus = bioStatus,
            displayModesSummary = displaySummary,
            accessLimitations = accessLimitations.distinct()
        )

        return BaselineProbeResult(
            environment = env,
            getpropAll = getpropAll,
            dumpsysFingerprint = dumpsysFp,
            dumpsysBiometric = dumpsysBio,
            dumpsysSurfaceFlinger = dumpsysSf,
            dumpsysDisplay = dumpsysDisp,
            dumpsysOverlay = dumpsysOverlay,
            lshalOutput = lshalRes,
            vintfManifests = vintfRes,
            serviceList = serviceListRes,
            sysfsFodNodes = sysfsRes,
            selinuxDenials = avcRes,
            initRcSnippets = initRcRes,
            discoveredBinaryPaths = discoveredBinaries,
            logcatBaseline = logcatBase,
            installedOverlayPackages = overlayPackages
        )
    }

    suspend fun captureLiveEnrollmentLogs(
        useRoot: Boolean,
        durationCheckOnly: Boolean = false
    ): String {
        val cmd = if (durationCheckOnly) {
            "logcat -d -t 250"
        } else if (useRoot) {
            "logcat -d -b main -b system -b events -t 2500"
        } else {
            "logcat -d -t 1500"
        }
        val res = ShellExecutor.exec(cmd, useRoot = useRoot, timeoutMs = 12_000L)
        return if (res.stdout.isNotBlank()) {
            res.stdout
        } else {
            "LOGCAT_UNAVAILABLE (exit=${res.exitCode}, err=${res.stderr.trim()})"
        }
    }

    private fun readReadableVintfFiles(limitations: MutableList<String>): String {
        val sb = StringBuilder()
        val candidates = mutableListOf(
            File("/vendor/etc/vintf/manifest.xml"),
            File("/system/etc/vintf/manifest.xml"),
            File("/system_ext/etc/vintf/manifest.xml"),
            File("/product/etc/vintf/manifest.xml")
        )
        File("/vendor/etc/vintf/manifest").listFiles()?.let { candidates.addAll(it) }
        var readCount = 0
        for (f in candidates) {
            if (f.exists() && f.isFile && f.canRead()) {
                try {
                    sb.appendLine("<!-- ${f.absolutePath} -->")
                    sb.appendLine(f.readText(Charsets.UTF_8))
                    readCount++
                } catch (_: Exception) {
                }
            }
        }
        if (readCount == 0) {
            limitations += "VINTF manifests unreadable without root."
        }
        return sb.toString()
    }

    private fun readReadableSysfsNodes(limitations: MutableList<String>): String {
        val sb = StringBuilder()
        val dirs = listOf("/sys/class/drm", "/sys/class/backlight", "/sys/kernel/oppo_display", "/sys/kernel/oplus_display")
        val keywords = listOf("hbm", "fod", "lhbm", "dim", "brightness")
        var anyRead = false
        for (dirPath in dirs) {
            val dir = File(dirPath)
            if (!dir.exists() || !dir.canRead()) continue
            dir.listFiles()?.forEach { child ->
                val targets = if (child.isDirectory && child.canRead()) {
                    child.listFiles()?.toList().orEmpty()
                } else {
                    listOf(child)
                }
                targets.filter { f ->
                    val n = f.name.lowercase()
                    keywords.any { n.contains(it) }
                }.forEach { node ->
                    if (node.isFile && node.canRead()) {
                        try {
                            sb.appendLine("=== ${node.absolutePath} ===")
                            sb.appendLine(node.readText(Charsets.UTF_8).trim())
                            anyRead = true
                        } catch (_: Exception) {
                        }
                    }
                }
            }
        }
        if (!anyRead) {
            limitations += "Sysfs HBM/FOD nodes unreadable in non-root mode."
        }
        return sb.toString()
    }

    private fun readReadableInitRcSnippets(limitations: MutableList<String>): String {
        val sb = StringBuilder()
        val kw = Regex("(fingerprint|fod|udfps|hbm|lhbm|goodix|fpc|silead|focal|egis|synaptics)", RegexOption.IGNORE_CASE)
        val dirs = listOf("/vendor/etc/init", "/system/etc/init", "/system_ext/etc/init", "/product/etc/init")
        var count = 0
        for (d in dirs) {
            val dir = File(d)
            if (!dir.exists() || !dir.canRead()) continue
            dir.listFiles()?.filter { it.isFile && it.canRead() && it.name.endsWith(".rc") }?.forEach { rc ->
                try {
                    rc.readLines().forEachIndexed { idx, line ->
                        if (kw.containsMatchIn(line) && count < 150) {
                            sb.appendLine("${rc.absolutePath}:${idx + 1}: $line")
                            count++
                        }
                    }
                } catch (_: Exception) {
                }
            }
        }
        if (count == 0) {
            limitations += "Init .rc scripts unreadable or contain no accessible FOD entries in non-root mode."
        }
        return sb.toString()
    }

    private fun scanReadableBinaries(limitations: MutableList<String>): List<String> {
        val kw = listOf("fingerprint", "biometric", "fod", "udfps", "goodix", "fpc", "silead", "focal", "egis", "synaptics")
        val dirs = listOf("/vendor/bin/hw", "/vendor/lib64/hw", "/vendor/lib64", "/system/lib64", "/system_ext/lib64")
        val found = mutableListOf<String>()
        for (d in dirs) {
            val dir = File(d)
            if (!dir.exists() || !dir.canRead()) continue
            dir.listFiles()?.forEach { f ->
                val name = f.name.lowercase()
                if (f.isFile && kw.any { name.contains(it) }) {
                    found += f.absolutePath
                }
            }
        }
        if (found.isEmpty()) {
            limitations += "HAL/FOD binaries in /vendor/bin/hw and /vendor/lib64 require root to list/disassemble."
        }
        return found.distinct()
    }

    private suspend fun probeCommand(
        cmd: String,
        useRoot: Boolean,
        limitations: MutableList<String>
    ): String {
        val res = ShellExecutor.exec(cmd, useRoot = useRoot, timeoutMs = 9_000L)
        if (!res.isSuccess && res.stdout.isBlank()) {
            val reason = res.stderr.trim().ifBlank { "exit=${res.exitCode}" }
            limitations += "Blocked/Unavailable [$cmd]: $reason"
        } else if (res.stderr.contains("Permission denied", ignoreCase = true) ||
            res.stderr.contains("Can't find service", ignoreCase = true)
        ) {
            limitations += "Partial access [$cmd]: ${res.stderr.trim().take(160)}"
        }
        return res.stdout
    }

    private fun parseProperties(raw: String): Map<String, String> {
        val map = LinkedHashMap<String, String>()
        val regex = Regex("^\\[(.+?)]: \\[(.*)]$")
        for (line in raw.lineSequence()) {
            val m = regex.matchEntire(line.trim()) ?: continue
            map[m.groupValues[1]] = m.groupValues[2]
        }
        return map
    }

    private fun detectGsiIndicators(props: Map<String, String>): List<String> {
        val indicators = mutableListOf<String>()
        val sysFp = props["ro.system.build.fingerprint"].orEmpty()
        val sysFlavor = props["ro.build.flavor"].orEmpty()
        val productName = props["ro.product.system.name"].orEmpty()
        if (sysFp.contains("gsi", true) || sysFlavor.contains("gsi", true) ||
            productName.contains("gsi", true) || productName.contains("treble", true)
        ) {
            indicators += "System build fingerprint/flavor identifies GSI ($productName / $sysFlavor)"
        }
        props.keys.filter { it.startsWith("persist.sys.phh.") || it.startsWith("ro.treble.") }
            .take(8)
            .forEach { key ->
                indicators += "$key=${props[key]}"
            }
        return indicators
    }

    private fun queryBiometricHardwareStatus(): String {
        val hasFpFeature = context.packageManager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)
        val mgrStatus = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val bm = context.getSystemService(BiometricManager::class.java)
            if (bm != null) {
                val res = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                } else {
                    @Suppress("DEPRECATION")
                    bm.canAuthenticate()
                }
                when (res) {
                    BiometricManager.BIOMETRIC_SUCCESS -> "BIOMETRIC_SUCCESS"
                    BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> "BIOMETRIC_ERROR_NO_HARDWARE"
                    BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> "BIOMETRIC_ERROR_HW_UNAVAILABLE"
                    BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "BIOMETRIC_ERROR_NONE_ENROLLED"
                    BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> "SECURITY_UPDATE_REQUIRED"
                    else -> "CODE_$res"
                }
            } else {
                "SERVICE_NULL"
            }
        } else {
            "API<29"
        }
        return "FEATURE_FINGERPRINT=$hasFpFeature | BiometricManager=$mgrStatus"
    }

    private fun queryDisplayModesSummary(): String {
        val dm = context.getSystemService(DisplayManager::class.java) ?: return "DisplayManager=null"
        val display = dm.getDisplay(Display.DEFAULT_DISPLAY) ?: return "DEFAULT_DISPLAY=null"
        val active = display.mode
        val modes = display.supportedModes.joinToString(", ") {
            "${it.physicalWidth}x${it.physicalHeight}@${it.refreshRate.toInt()}Hz"
        }
        val hdr = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            display.hdrCapabilities?.supportedHdrTypes?.joinToString(",") ?: "none"
        } else "n/a"
        return "Active=${active.physicalWidth}x${active.physicalHeight}@${active.refreshRate.toInt()}Hz | Modes=[$modes] | HDR=[$hdr]"
    }

    private fun queryInstalledFodOverlays(): List<String> {
        return try {
            @Suppress("DEPRECATION")
            val pkgs = context.packageManager.getInstalledPackages(0)
            pkgs.map { it.packageName }
                .filter {
                    val l = it.lowercase()
                    l.contains("fod") || l.contains("udfps") || l.contains("treble") ||
                        l.contains("overlay") || l.contains("fingerprint") || l.contains("biometric")
                }
                .sorted()
        } catch (e: Exception) {
            emptyList()
        }
    }
}
