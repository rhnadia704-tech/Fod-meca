package com.example.engine

import android.content.Context
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.hardware.display.DisplayManager
import android.os.Build
import android.os.Environment
import android.view.Display
import com.example.model.EnvironmentSnapshot
import com.example.model.FileProvenanceArtifact
import com.example.model.OverlayDeepInspection
import com.example.model.SysfsTransition
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

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
    val installedOverlayPackages: List<String>,
    val logcatAnchorTimestamp: String = "",
    val discoveredSysfsPaths: List<String> = emptyList(),
    val baselineSysfsMap: Map<String, String> = emptyMap(),
    val baselineDmesgLines: List<String> = emptyList(),
    val baselineSurfaceFlingerLayers: List<String> = emptyList(),
    val overlayInspections: List<OverlayDeepInspection> = emptyList(),
    val fileProvenance: List<FileProvenanceArtifact> = emptyList(),
    val overlayDeepInspect: String = "",
    val fileProvenanceIndex: String = ""
)

data class LivePollSnapshot(
    val observedLogCount: Int,
    val sysfsValues: Map<String, String>,
    val newDmesgCount: Int,
    val surfaceFlingerFodLayers: List<String>,
    val fodActivityDetected: Boolean
)

data class FinalSessionCapture(
    val liveLogcat: String,
    val dmesgDelta: String,
    val surfaceFlingerLiveDelta: String,
    val sysfsTransitions: List<SysfsTransition>
)

class SystemProbeCollector(private val context: Context) {

    private val fodKeywordRegex = Regex(
        "(fingerprint|biometric|udfps|fod|hbm|lhbm|dimlayer|goodix|gf_|fp_|disp_param|touch_dev|avc:\\s*denied)",
        RegexOption.IGNORE_CASE
    )

    private val defaultSysfsCandidates = listOf(
        "/sys/class/drm/card0-DSI-1/disp_param",
        "/sys/class/drm/card0-DSI-1/fod_status",
        "/sys/class/drm/card0-DSI-1/hbm",
        "/sys/class/drm/card0-DSI-1/lhbm",
        "/sys/devices/virtual/touch/touch_dev/fod_press_status",
        "/sys/devices/virtual/touch/touch_dev/fod_longpress_gesture_enabled",
        "/sys/devices/virtual/touch/touch_dev/fod_status",
        "/sys/class/touch/touch_dev/fod_press_status",
        "/sys/class/backlight/panel0-backlight/brightness",
        "/sys/kernel/oppo_display/hbm",
        "/sys/kernel/oppo_display/dimlayer_bl_en",
        "/sys/kernel/oplus_display/hbm",
        "/sys/kernel/oplus_display/dimlayer_bl_en"
    )

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
            accessLimitations += "Root mode disabled in Settings: dumpsys, lshal, dmesg, cmd overlay, vendor ELF binaries, full sysfs, and init.rc require root (su)."
        }

        val effectiveRoot = useRoot && rootGranted

        val getpropRes = ShellExecutor.exec("getprop", useRoot = false)
        val getpropAll = getpropRes.stdout
        if (!getpropRes.isSuccess) {
            accessLimitations += "getprop returned exit=${getpropRes.exitCode}: ${getpropRes.stderr.trim()}"
        }

        val propMap = parseProperties(getpropAll)
        val gsiIndicators = detectGsiIndicators(propMap)

        val dumpsysFp: String
        val dumpsysBio: String
        val dumpsysSf: String
        val dumpsysDisp: String
        val dumpsysOverlay: String
        val lshalRes: String
        val serviceListRes: String
        val baselineSfLayers: List<String>

        if (effectiveRoot) {
            dumpsysFp = probeCommand("dumpsys fingerprint", true, accessLimitations)
            dumpsysBio = probeCommand("dumpsys biometric", true, accessLimitations)
            dumpsysSf = probeCommand("dumpsys SurfaceFlinger", true, accessLimitations)
            dumpsysDisp = probeCommand("dumpsys display", true, accessLimitations)
            dumpsysOverlay = probeCommand("cmd overlay list", true, accessLimitations)
                .ifBlank { probeCommand("dumpsys overlay", true, accessLimitations) }
            lshalRes = probeCommand("lshal -i --neat", true, accessLimitations)
            serviceListRes = probeCommand("service list", true, accessLimitations)
            baselineSfLayers = ShellExecutor.exec("dumpsys SurfaceFlinger --list", useRoot = true, timeoutMs = 5_000L)
                .stdout.lines()
                .map { it.trim() }
                .filter { it.isNotBlank() && isInterestingSfLayer(it) }
        } else {
            dumpsysFp = ""
            dumpsysBio = ""
            dumpsysSf = ""
            dumpsysDisp = ""
            dumpsysOverlay = ""
            lshalRes = ""
            serviceListRes = ""
            baselineSfLayers = emptyList()
            accessLimitations += "Privileged diagnostics skipped in non-root mode (dumpsys fingerprint/biometric/SurfaceFlinger/display, cmd overlay, lshal, service list, dmesg)."
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

        val discoveredSysfsPaths = discoverSysfsNodePaths(effectiveRoot)
        val (sysfsMap, sysfsText) = readSysfsMapAndText(effectiveRoot, discoveredSysfsPaths, accessLimitations)

        // Fix: always run getenforce with effectiveRoot and fall back to /sys/fs/selinux/enforce
        val selinuxMode = resolveSelinuxMode(effectiveRoot, propMap)

        val baselineDmesgLines = if (effectiveRoot) {
            captureFilteredDmesgLines(effectiveRoot = true)
        } else {
            emptyList()
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
                "grep -rnE 'fingerprint|fod|udfps|hbm|lhbm|goodix|fpc|silead|focal|egis|synaptics|disp_param' /vendor/etc/init /odm/etc/init /system/etc/init /system_ext/etc/init /product/etc/init 2>/dev/null | head -n 220",
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

        val anchorTs = resolveLogcatAnchorTimestamp(effectiveRoot)

        val bioStatus = queryBiometricHardwareStatus()
        val displaySummary = queryDisplayModesSummary()
        val overlayPackages = queryInstalledFodOverlays()

        val provenanceBundle = DynamicProvenanceInspector.inspectAll(
            context = context,
            dumpsysOverlayList = dumpsysOverlay,
            installedOverlayPackages = overlayPackages,
            getpropAll = getpropAll,
            initRcSnippets = initRcRes,
            lshalOutput = lshalRes,
            vintfManifests = vintfRes,
            effectiveRoot = effectiveRoot,
            accessLimitations = accessLimitations
        )

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
            sysfsFodNodes = sysfsText,
            selinuxDenials = avcRes,
            initRcSnippets = initRcRes,
            discoveredBinaryPaths = discoveredBinaries,
            logcatBaseline = logcatBase,
            installedOverlayPackages = overlayPackages,
            logcatAnchorTimestamp = anchorTs,
            discoveredSysfsPaths = discoveredSysfsPaths,
            baselineSysfsMap = sysfsMap,
            baselineDmesgLines = baselineDmesgLines,
            baselineSurfaceFlingerLayers = baselineSfLayers,
            overlayInspections = provenanceBundle.overlayInspections,
            fileProvenance = provenanceBundle.fileProvenance,
            overlayDeepInspect = provenanceBundle.overlayDeepInspectText,
            fileProvenanceIndex = provenanceBundle.fileProvenanceIndexText
        )
    }

    suspend fun captureLivePollSnapshot(
        baseline: BaselineProbeResult,
        effectiveRoot: Boolean
    ): LivePollSnapshot {
        val anchor = baseline.logcatAnchorTimestamp
        val logCmd = when {
            effectiveRoot && anchor.isNotBlank() ->
                "logcat -d -b main -b system -b events -T '$anchor' | grep -iE 'fingerprint|biometric|udfps|fod|hbm|lhbm|goodix|enroll|onacquired|onfinger'"
            anchor.isNotBlank() ->
                "logcat -d -T '$anchor' | grep -iE 'fingerprint|biometric|udfps|fod|hbm|lhbm|goodix|enroll'"
            else ->
                "logcat -d -t 300 | grep -iE 'fingerprint|biometric|udfps|fod|hbm|lhbm|goodix|enroll'"
        }
        val logRes = ShellExecutor.exec(logCmd, useRoot = effectiveRoot, timeoutMs = 4_000L)
        val observedLogs = logRes.stdout.lineSequence().count { it.isNotBlank() }

        val currentSysfs = readSysfsMapQuick(effectiveRoot, baseline.discoveredSysfsPaths.take(20))
        val anySysfsChanged = currentSysfs.any { (path, value) ->
            val before = baseline.baselineSysfsMap[path]
            before != null && value != before
        }

        val currentDmesg = if (effectiveRoot) captureFilteredDmesgLines(true) else emptyList()
        val newDmesg = diffNewTailLines(baseline.baselineDmesgLines, currentDmesg)

        val sfLayers = if (effectiveRoot) {
            ShellExecutor.exec("dumpsys SurfaceFlinger --list", useRoot = true, timeoutMs = 3_500L)
                .stdout.lines()
                .map { it.trim() }
                .filter { it.isNotBlank() && isInterestingSfLayer(it) }
        } else {
            emptyList()
        }
        val sfDelta = sfLayers.filter { it !in baseline.baselineSurfaceFlingerLayers }

        return LivePollSnapshot(
            observedLogCount = observedLogs,
            sysfsValues = currentSysfs,
            newDmesgCount = newDmesg.size,
            surfaceFlingerFodLayers = sfDelta,
            fodActivityDetected = anySysfsChanged || sfDelta.isNotEmpty() || newDmesg.isNotEmpty() || observedLogs > 0
        )
    }

    suspend fun captureFinalSessionDiff(
        baseline: BaselineProbeResult,
        liveSysfsHistory: Map<String, List<String>>,
        liveObservedSfLayers: Set<String>
    ): FinalSessionCapture {
        val effectiveRoot = baseline.environment.rootGranted
        val liveLogcat = captureLiveEnrollmentLogs(
            useRoot = effectiveRoot,
            anchorTimestamp = baseline.logcatAnchorTimestamp,
            durationCheckOnly = false
        )

        val finalDmesgLines = if (effectiveRoot) captureFilteredDmesgLines(true) else emptyList()
        val dmesgDeltaLines = diffNewTailLines(baseline.baselineDmesgLines, finalDmesgLines)
        val dmesgDeltaText = when {
            !effectiveRoot -> "DMESG_UNAVAILABLE (root required for kernel dmesg buffer)"
            dmesgDeltaLines.isEmpty() -> "NO_NEW_FOD_DMESG_EVENTS (${finalDmesgLines.size} total filtered baseline kernel lines)"
            else -> dmesgDeltaLines.joinToString("\n")
        }

        val finalSfLayers = if (effectiveRoot) {
            ShellExecutor.exec("dumpsys SurfaceFlinger --list", useRoot = true, timeoutMs = 4_000L)
                .stdout.lines()
                .map { it.trim() }
                .filter { it.isNotBlank() && isInterestingSfLayer(it) }
        } else {
            emptyList()
        }
        val allLiveSfDelta = (liveObservedSfLayers + finalSfLayers)
            .filter { it !in baseline.baselineSurfaceFlingerLayers }
            .distinct()
        val sfDeltaText = when {
            !effectiveRoot -> "SURFACEFLINGER_LIVE_UNAVAILABLE (root required)"
            allLiveSfDelta.isEmpty() -> "NO_NEW_FOD_SURFACE_LAYER_OBSERVED"
            else -> allLiveSfDelta.joinToString("\n")
        }

        val finalSysfsMap = readSysfsMapQuick(effectiveRoot, baseline.discoveredSysfsPaths.take(30))
        val transitions = baseline.discoveredSysfsPaths.take(30).mapNotNull { path ->
            val before = baseline.baselineSysfsMap[path] ?: return@mapNotNull null
            val liveList = liveSysfsHistory[path].orEmpty().distinct()
            val after = finalSysfsMap[path] ?: before
            val changed = (before != after) || liveList.any { it != before }
            SysfsTransition(
                nodePath = path,
                beforeValue = before,
                liveValues = liveList,
                afterValue = after,
                changed = changed
            )
        }

        return FinalSessionCapture(
            liveLogcat = liveLogcat,
            dmesgDelta = dmesgDeltaText,
            surfaceFlingerLiveDelta = sfDeltaText,
            sysfsTransitions = transitions
        )
    }

    suspend fun captureLiveEnrollmentLogs(
        useRoot: Boolean,
        anchorTimestamp: String = "",
        durationCheckOnly: Boolean = false
    ): String {
        if (!durationCheckOnly && anchorTimestamp.isNotBlank()) {
            val anchoredCmd = if (useRoot) {
                "logcat -d -b main -b system -b events -T '$anchorTimestamp'"
            } else {
                "logcat -d -T '$anchorTimestamp'"
            }
            val anchoredRes = ShellExecutor.exec(anchoredCmd, useRoot = useRoot, timeoutMs = 12_000L)
            if (anchoredRes.isSuccess && anchoredRes.stdout.isNotBlank()) {
                return anchoredRes.stdout
            }
        }

        val cmd = if (durationCheckOnly) {
            "logcat -d -t 250"
        } else if (useRoot) {
            "logcat -d -b main -b system -b events -t 3000"
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

    private suspend fun resolveSelinuxMode(
        effectiveRoot: Boolean,
        propMap: Map<String, String>
    ): String {
        val primary = ShellExecutor.exec("getenforce", useRoot = effectiveRoot, timeoutMs = 4_000L)
            .stdout.trim()
        if (primary.equals("Enforcing", true) ||
            primary.equals("Permissive", true) ||
            primary.equals("Disabled", true)
        ) {
            return primary
        }
        if (effectiveRoot) {
            val sysfsEnforce = ShellExecutor.exec("cat /sys/fs/selinux/enforce", useRoot = true, timeoutMs = 3_000L)
                .stdout.trim()
            when (sysfsEnforce) {
                "1" -> return "Enforcing"
                "0" -> return "Permissive"
            }
        }
        return propMap["ro.boot.selinux"]?.takeIf { it.isNotBlank() } ?: "UNKNOWN"
    }

    private suspend fun resolveLogcatAnchorTimestamp(effectiveRoot: Boolean): String {
        val shellTs = ShellExecutor.exec("date '+%m-%d %H:%M:%S.000'", useRoot = effectiveRoot, timeoutMs = 3_000L)
            .stdout.trim()
        if (Regex("\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d{3}").matches(shellTs)) {
            return shellTs
        }
        return SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.US).format(Date())
    }

    private suspend fun discoverSysfsNodePaths(effectiveRoot: Boolean): List<String> {
        val found = linkedSetOf<String>()
        defaultSysfsCandidates.forEach { if (File(it).exists() || effectiveRoot) found += it }

        if (effectiveRoot) {
            val dynamicFind = ShellExecutor.exec(
                "find /sys/class/drm /sys/devices/virtual/touch /sys/class/touch /sys/kernel/oppo_display /sys/kernel/oplus_display /sys/devices/platform -maxdepth 4 \\( -iname '*fod*' -o -iname '*hbm*' -o -iname '*lhbm*' -o -iname '*udfps*' -o -iname '*disp_param*' -o -iname '*dimlayer*' -o -iname '*finger*' \\) 2>/dev/null | head -n 50",
                useRoot = true,
                timeoutMs = 5_000L
            )
            dynamicFind.stdout.lineSequence()
                .map { it.trim() }
                .filter { it.startsWith("/sys/") && !it.contains("No such file") }
                .forEach { found += it }
        }
        return found.toList()
    }

    private suspend fun readSysfsMapAndText(
        effectiveRoot: Boolean,
        paths: List<String>,
        limitations: MutableList<String>
    ): Pair<Map<String, String>, String> {
        if (!effectiveRoot) {
            val text = readReadableSysfsNodes(limitations)
            val map = parseSysfsSectionsToMap(text)
            return map to text
        }

        val validPaths = paths.filter { p ->
            !p.contains("'") && !p.contains("\"") && !p.contains(";") &&
                !p.contains(">") && !p.contains("<") && !p.contains("$")
        }.take(45)

        if (validPaths.isEmpty()) {
            return emptyMap<String, String>() to ""
        }

        val joined = validPaths.joinToString(" ") { "'$it'" }
        val res = ShellExecutor.exec(
            "for p in $joined; do if [ -f \"\$p\" ]; then echo \"=== \$p ===\"; cat \"\$p\" 2>&1; fi; done",
            useRoot = true,
            timeoutMs = 7_000L
        )
        val map = parseSysfsSectionsToMap(res.stdout)
        return map to res.stdout
    }

    private suspend fun readSysfsMapQuick(
        effectiveRoot: Boolean,
        paths: List<String>
    ): Map<String, String> {
        if (paths.isEmpty()) return emptyMap()
        if (!effectiveRoot) {
            val out = LinkedHashMap<String, String>()
            paths.forEach { p ->
                val f = File(p)
                if (f.isFile && f.canRead()) {
                    try {
                        out[p] = f.readText(Charsets.UTF_8).trim().take(200)
                    } catch (_: Exception) {
                    }
                }
            }
            return out
        }
        val joined = paths.filter {
            !it.contains("'") && !it.contains(";") && !it.contains(">") && !it.contains("<") && !it.contains("$")
        }.joinToString(" ") { "'$it'" }
        if (joined.isBlank()) return emptyMap()
        val res = ShellExecutor.exec(
            "for p in $joined; do if [ -f \"\$p\" ]; then echo \"=== \$p ===\"; head -c 256 \"\$p\" 2>&1; echo ''; fi; done",
            useRoot = true,
            timeoutMs = 4_500L
        )
        return parseSysfsSectionsToMap(res.stdout)
    }

    private fun parseSysfsSectionsToMap(raw: String): Map<String, String> {
        val map = LinkedHashMap<String, String>()
        val sections = raw.split("=== ").map { it.trim() }.filter { it.isNotBlank() }
        for (block in sections) {
            val lines = block.lines()
            val nodePath = lines.firstOrNull()?.removeSuffix("===")?.trim() ?: continue
            if (!nodePath.startsWith("/")) continue
            val value = lines.drop(1).joinToString(" ").trim().take(220)
            if (value.contains("No such file", true)) continue
            map[nodePath] = value.ifBlank { "<empty>" }
        }
        return map
    }

    private suspend fun captureFilteredDmesgLines(effectiveRoot: Boolean): List<String> {
        if (!effectiveRoot) return emptyList()
        val res = ShellExecutor.exec(
            "dmesg | grep -iE 'fod|udfps|goodix|gf_|fp_|fingerprint|hbm|lhbm|disp_param|dsi|touch_dev|avc:' | tail -n 160",
            useRoot = true,
            timeoutMs = 5_000L
        )
        return res.stdout.lines()
            .map { it.trim() }
            .filter { it.isNotBlank() && !it.contains("read kernel buffer", true) }
    }

    internal fun diffNewTailLines(before: List<String>, after: List<String>): List<String> {
        if (after.isEmpty()) return emptyList()
        if (before.isEmpty()) return after
        val lastBefore = before.last()
        val lastMatchIdx = after.lastIndexOf(lastBefore)
        return if (lastMatchIdx >= 0 && lastMatchIdx < after.lastIndex) {
            after.subList(lastMatchIdx + 1, after.size)
        } else if (lastMatchIdx == after.lastIndex) {
            emptyList()
        } else {
            val beforeSet = before.toHashSet()
            after.filter { it !in beforeSet }
        }
    }

    private fun isInterestingSfLayer(line: String): Boolean {
        val l = line.lowercase()
        return l.contains("udfps") || l.contains("fod") || l.contains("fingerprint") ||
            l.contains("hbm") || l.contains("lhbm") || l.contains("dim") || l.contains("biometric")
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
        val keywords = listOf("hbm", "fod", "lhbm", "dim", "brightness", "disp_param")
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
        } catch (_: Exception) {
            emptyList()
        }
    }
}
