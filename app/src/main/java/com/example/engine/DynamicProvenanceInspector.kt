package com.example.engine

import android.content.Context
import android.content.pm.PackageManager
import android.content.res.Resources
import android.util.Log
import com.example.model.FileProvenanceArtifact
import com.example.model.OverlayDeepInspection
import java.io.ByteArrayInputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipInputStream

private const val TAG = "DynamicProvenance"

data class DynamicProvenanceBundle(
    val overlayInspections: List<OverlayDeepInspection>,
    val fileProvenance: List<FileProvenanceArtifact>,
    val overlayDeepInspectText: String,
    val fileProvenanceIndexText: String
)

object DynamicProvenanceInspector {

    private val fodKeywordsRegex = Regex(
        "(fod|udfps|fingerprint|biometric|hbm|lhbm|dimlayer|doze_brightness|burn_in|illumination|optical|goodix|fpc|silead|focal|egis|synaptics|disp_param|touch_dev|xiaomi\\.fingerprint|oplus\\.biometrics|phh\\.fod|treble)",
        RegexOption.IGNORE_CASE
    )

    private val overlayCandidateRegex = Regex(
        "(fod|udfps|fingerprint|biometric|hbm|lhbm|display|systemui|treble|phh|overlay)",
        RegexOption.IGNORE_CASE
    )

    // Well-known AOSP / OEM / Treble resource keys checked via Resources.getIdentifier ONLY AFTER dynamic ARSC discovery
    private val probeResourceSeeds = listOf(
        "bool" to "config_supportsUdfps",
        "bool" to "config_udfps_illumination_transition",
        "bool" to "config_displayBlanksAfterDoze",
        "bool" to "config_dozeAfterScreenOff",
        "bool" to "config_hbm_enabled",
        "bool" to "config_udfps_hbm",
        "bool" to "config_use_udfps",
        "integer" to "config_udfps_illumination_transition_ms",
        "integer" to "config_fingerprintMaxTemplatesPerUser",
        "string" to "config_udfps_hbm_sysfs_node",
        "string" to "config_udfps_illuminator_path",
        "string" to "config_dozeUdfpsLongPressSensorType",
        "array" to "config_biometric_sensors",
        "array" to "config_udfps_sensor_props",
        "array" to "config_sf_udfps_illuminator_config",
        "array" to "config_display_no_service_when_dozing"
    )

    suspend fun inspectAll(
        context: Context,
        dumpsysOverlayList: String,
        installedOverlayPackages: List<String>,
        getpropAll: String,
        initRcSnippets: String,
        lshalOutput: String,
        vintfManifests: String,
        effectiveRoot: Boolean,
        accessLimitations: MutableList<String>
    ): DynamicProvenanceBundle {
        val overlayInspections = inspectOverlays(
            context = context,
            dumpsysOverlayList = dumpsysOverlayList,
            installedPackages = installedOverlayPackages,
            effectiveRoot = effectiveRoot
        )

        val provenance = mutableListOf<FileProvenanceArtifact>()

        // 1. Add all inspected overlays as provenance entries
        overlayInspections.forEachIndexed { idx, ov ->
            val contents = mutableListOf<String>()
            contents += "targetPackage=${ov.targetPackage.ifBlank { "UNKNOWN" }} | enabled=${ov.isEnabled} | static=${ov.isStatic} | priority=${ov.priority}"
            contents.addAll(ov.manifestSummary.take(8))
            contents.addAll(ov.fodConfigEntries.take(25))
            provenance += FileProvenanceArtifact(
                id = "prov_ov_${idx}_${ov.packageName.hashCode()}",
                category = "OVERLAY_APK",
                filePath = ov.apkPath,
                directory = ov.directory,
                matchedSymbolOrKey = ov.packageName,
                importantContents = contents.distinct().take(30),
                accessNote = if (ov.apkPath == "UNKNOWN") "APK path unresolved on device" else null
            )
        }

        // 2. Dynamic .prop files provenance scan
        provenance += discoverPropFilesProvenance(getpropAll, effectiveRoot, accessLimitations)

        // 3. Parse init.rc provenance directly from dynamic grep + file grouping
        provenance += buildInitRcProvenance(initRcSnippets)

        // 4. Dynamic XML discovery (permissions, sysconfig, displayconfig, vintf)
        val extraHalKeywords = extractDynamicHalKeywords(lshalOutput, vintfManifests)
        provenance += discoverSystemXmlProvenance(effectiveRoot, extraHalKeywords)

        // 5. Dynamic SELinux policy files (.cil / contexts / policy)
        provenance += discoverSelinuxPolicyProvenance(effectiveRoot)

        // 6. Dynamic SystemUI / Framework / Biometric APEX locator & hook scan
        provenance += discoverSystemUiAndFrameworkProvenance(context, effectiveRoot)

        val distinctProvenance = provenance.distinctBy { "${it.category}::${it.filePath}::${it.matchedSymbolOrKey}" }
        val overlayText = serializeOverlayDeepInspect(overlayInspections)
        val provenanceText = serializeFileProvenanceIndex(distinctProvenance)

        return DynamicProvenanceBundle(
            overlayInspections = overlayInspections,
            fileProvenance = distinctProvenance,
            overlayDeepInspectText = overlayText,
            fileProvenanceIndexText = provenanceText
        )
    }

    private suspend fun inspectOverlays(
        context: Context,
        dumpsysOverlayList: String,
        installedPackages: List<String>,
        effectiveRoot: Boolean
    ): List<OverlayDeepInspection> {
        val stateMap = LinkedHashMap<String, Boolean>()
        dumpsysOverlayList.lineSequence().forEach { line ->
            val t = line.trim()
            if (t.startsWith("[x]", true) || t.startsWith("[ ]", true)) {
                val enabled = t.startsWith("[x]", true)
                val pkg = t.drop(3).trim().substringBefore(" ")
                if (pkg.isNotBlank()) stateMap[pkg] = enabled
            } else if (t.contains("STATE_ENABLED") || t.contains("STATE_DISABLED")) {
                val enabled = t.contains("STATE_ENABLED")
                val pkg = t.substringBefore(":").substringBefore(" ").trim()
                if (pkg.isNotBlank()) stateMap[pkg] = enabled
            }
        }

        // Dump full overlay registry in one pass if root is granted (`dumpsys overlay`)
        val dumpMap = if (effectiveRoot) {
            val rawDump = ShellExecutor.exec("dumpsys overlay", useRoot = true, timeoutMs = 8_000L).stdout
            parseDumpsysOverlayBlocks(rawDump)
        } else {
            emptyMap()
        }

        // Collect candidates dynamically:
        // - Any overlay whose package matches FOD/UDFPS/Biometric/Display/Treble/SystemUI/Overlay
        // - Plus any enabled overlay targeting com.android.systemui / android / com.android.settings from dumpsys overlay
        val candidatePackages = linkedSetOf<String>()
        stateMap.keys.filter { pkg ->
            overlayCandidateRegex.containsMatchIn(pkg) ||
                stateMap[pkg] == true && dumpMap[pkg]?.targetPackage in setOf("com.android.systemui", "android", "com.android.settings")
        }.forEach { candidatePackages += it }
        installedPackages.filter { overlayCandidateRegex.containsMatchIn(it) }.forEach { candidatePackages += it }
        dumpMap.entries
            .filter { (_, info) ->
                overlayCandidateRegex.containsMatchIn(info.packageName) ||
                    (info.isEnabled && info.targetPackage in setOf("com.android.systemui", "android"))
            }
            .forEach { candidatePackages += it.key }

        // If root is active, dynamically scan overlay partition directories for APK filenames not yet matched
        val apkIndex = if (effectiveRoot) {
            ShellExecutor.exec(
                "find /system /system_ext /product /vendor /odm /apex -maxdepth 5 -iname '*.apk' 2>/dev/null | grep -iE 'overlay|fod|udfps|fingerprint|biometric|systemui|framework-res|treble' | head -n 160",
                useRoot = true,
                timeoutMs = 6_000L
            ).stdout.lines().map { it.trim() }.filter { it.startsWith("/") }
        } else {
            emptyList()
        }

        val pm = context.packageManager
        val inspections = mutableListOf<OverlayDeepInspection>()

        for (pkg in candidatePackages.take(40)) {
            val dumpInfo = dumpMap[pkg]
            val enabled = stateMap[pkg] ?: dumpInfo?.isEnabled ?: false
            var targetPkg = dumpInfo?.targetPackage.orEmpty()
            var apkPath = dumpInfo?.baseCodePath.orEmpty()
            val priority = dumpInfo?.priority ?: 0
            val isStatic = dumpInfo?.isStatic ?: false

            // Fallback 1: PackageManager applicationInfo
            if (apkPath.isBlank()) {
                apkPath = runCatching {
                    @Suppress("DEPRECATION")
                    pm.getApplicationInfo(pkg, PackageManager.MATCH_UNINSTALLED_PACKAGES or PackageManager.MATCH_ALL).sourceDir.orEmpty()
                }.getOrDefault("")
            }

            // Fallback 2: `pm path <pkg>`
            if (apkPath.isBlank()) {
                val pmOut = ShellExecutor.exec("pm path '$pkg'", useRoot = effectiveRoot, timeoutMs = 3_000L).stdout
                apkPath = pmOut.lineSequence()
                    .firstOrNull { it.startsWith("package:") }
                    ?.removePrefix("package:")
                    ?.trim()
                    .orEmpty()
            }

            // Fallback 3: Dynamic partition APK name lookup
            if (apkPath.isBlank()) {
                val shortToken = pkg.substringAfterLast('.').lowercase()
                apkPath = apkIndex.firstOrNull { path ->
                    path.contains(shortToken, ignoreCase = true) || path.contains(pkg, ignoreCase = true)
                }.orEmpty()
            }

            val finalApkPath = apkPath.ifBlank { "UNKNOWN" }
            val directory = if (finalApkPath.contains("/")) finalApkPath.substringBeforeLast('/') else "UNKNOWN"

            // Inspect APK binary XML / ARSC + PackageManager live resources
            val manifestSummary = mutableListOf<String>()
            val configEntries = mutableListOf<String>()

            if (finalApkPath != "UNKNOWN") {
                val readRes = ShellExecutor.readBinaryFile(finalApkPath, effectiveRoot, maxBytes = 6 * 1024 * 1024)
                if (readRes.bytes != null) {
                    val apkParsed = parseApkBinaryFodDetails(readRes.bytes)
                    if (targetPkg.isBlank() && apkParsed.inferredTargetPackage.isNotBlank()) {
                        targetPkg = apkParsed.inferredTargetPackage
                    }
                    manifestSummary += apkParsed.manifestSignals
                    configEntries += apkParsed.fodResourceStrings

                    // Live Android Resources lookup using discovered resource names + probe seeds
                    val resolvedValues = resolvePackageResourceValues(
                        pm = pm,
                        pkg = pkg,
                        discoveredKeys = apkParsed.discoveredResourceKeys
                    )
                    configEntries += resolvedValues
                } else if (readRes.accessError != null) {
                    manifestSummary += "APK read restricted: ${readRes.accessError}"
                }
            }

            // Even if APK bytes couldn't be read, try PackageManager.getResourcesForApplication directly
            if (configEntries.isEmpty()) {
                configEntries += resolvePackageResourceValues(pm, pkg, emptyList())
            }

            // Also inspect target package resources dynamically for enabled FOD overlays so we see effective override values
            if (targetPkg.isNotBlank() && enabled && overlayCandidateRegex.containsMatchIn(pkg)) {
                val manifestTag = "Overrides targetPackage=$targetPkg"
                if (manifestTag !in manifestSummary) manifestSummary += manifestTag
            }

            inspections += OverlayDeepInspection(
                packageName = pkg,
                targetPackage = targetPkg,
                apkPath = finalApkPath,
                directory = directory,
                isEnabled = enabled,
                isStatic = isStatic,
                priority = priority,
                manifestSummary = manifestSummary.distinct().take(15),
                fodConfigEntries = configEntries.distinct().take(45),
                rawDumpNote = dumpInfo?.rawSnippet.orEmpty()
            )
        }

        // Prioritize enabled overlays and explicit FOD/UDFPS overlays first
        return inspections.sortedWith(
            compareByDescending<OverlayDeepInspection> { it.isEnabled }
                .thenByDescending { fodKeywordsRegex.containsMatchIn(it.packageName) || it.fodConfigEntries.isNotEmpty() }
                .thenBy { it.packageName }
        )
    }

    internal data class DumpsysOverlayBlock(
        val packageName: String,
        val targetPackage: String = "",
        val baseCodePath: String = "",
        val isEnabled: Boolean = false,
        val isStatic: Boolean = false,
        val priority: Int = 0,
        val rawSnippet: String = ""
    )

    internal fun parseDumpsysOverlayBlocks(raw: String): Map<String, DumpsysOverlayBlock> {
        val out = LinkedHashMap<String, DumpsysOverlayBlock>()
        if (raw.isBlank()) return out

        var currentPkg: String? = null
        var targetPkg = ""
        var baseCodePath = ""
        var isEnabled = false
        var isStatic = false
        var priority = 0
        val snippet = StringBuilder()

        fun flush() {
            val pkg = currentPkg ?: return
            if (!out.containsKey(pkg) || baseCodePath.isNotBlank()) {
                out[pkg] = DumpsysOverlayBlock(
                    packageName = pkg,
                    targetPackage = targetPkg,
                    baseCodePath = baseCodePath,
                    isEnabled = isEnabled,
                    isStatic = isStatic,
                    priority = priority,
                    rawSnippet = snippet.toString().trim().take(500)
                )
            }
        }

        val headerRegex = Regex("^([a-zA-Z0-9._-]+):\\d+\\s*\\{?$|^Package \\[([a-zA-Z0-9._-]+)\\]|^([a-zA-Z0-9._-]+)\\s*\\{?$")
        for (line in raw.lineSequence()) {
            val t = line.trim()
            val headerMatch = headerRegex.matchEntire(t)
            if (headerMatch != null && !t.contains("=")) {
                val candidate = listOf(headerMatch.groupValues[1], headerMatch.groupValues[2], headerMatch.groupValues[3])
                    .firstOrNull { it.contains(".") }
                if (candidate != null) {
                    flush()
                    currentPkg = candidate
                    targetPkg = ""
                    baseCodePath = ""
                    isEnabled = false
                    isStatic = false
                    priority = 0
                    snippet.clear()
                    continue
                }
            }
            if (currentPkg == null) continue
            if (t.startsWith("mTargetPackageName")) targetPkg = t.substringAfter("=").trim()
            else if (t.startsWith("targetPackageName")) targetPkg = t.substringAfter(":").substringAfter("=").trim()
            else if (t.startsWith("mBaseCodePath") || t.startsWith("baseCodePath")) {
                baseCodePath = t.substringAfter("=").substringAfter(":").trim()
            } else if (t.startsWith("mState")) {
                isEnabled = t.contains("STATE_ENABLED", true)
            } else if (t.startsWith("mIsStatic") || t.startsWith("isStatic")) {
                isStatic = t.contains("true", true)
            } else if (t.startsWith("mPriority") || t.startsWith("priority")) {
                priority = t.substringAfter("=").substringAfter(":").trim().toIntOrNull() ?: 0
            }
            if (snippet.length < 480) snippet.appendLine(t)
        }
        flush()
        return out
    }

    internal data class ParsedApkSignals(
        val inferredTargetPackage: String,
        val manifestSignals: List<String>,
        val discoveredResourceKeys: List<Pair<String, String>>,
        val fodResourceStrings: List<String>
    )

    internal fun parseApkBinaryFodDetails(apkBytes: ByteArray): ParsedApkSignals {
        val manifestSignals = mutableListOf<String>()
        val discoveredKeys = mutableListOf<Pair<String, String>>()
        val fodResourceStrings = mutableListOf<String>()
        var inferredTarget = ""

        runCatching {
            ZipInputStream(ByteArrayInputStream(apkBytes)).use { zip ->
                var entry = zip.nextEntry
                while (entry != null) {
                    if (!entry.isDirectory) {
                        val name = entry.name
                        when {
                            name == "AndroidManifest.xml" -> {
                                val data = zip.readBytes()
                                val poolStrings = extractStringsFromAndroidBinaryChunks(data)
                                if (inferredTarget.isBlank()) {
                                    inferredTarget = poolStrings.firstOrNull {
                                        it == "com.android.systemui" || it == "android" || it == "com.android.settings"
                                    }.orEmpty()
                                }
                                poolStrings.filter { s ->
                                    s.length in 3..140 && (
                                        fodKeywordsRegex.containsMatchIn(s) ||
                                            s.startsWith("ro.") || s.startsWith("persist.") ||
                                            s.contains("overlay", true) || s.contains("target", true)
                                        )
                                }.distinct().take(14).forEach { manifestSignals += "manifest: $it" }
                            }
                            name == "resources.arsc" -> {
                                val data = zip.readBytes()
                                val poolStrings = extractStringsFromAndroidBinaryChunks(data)
                                poolStrings.forEach { s ->
                                    if (s.length in 3..160 && fodKeywordsRegex.containsMatchIn(s)) {
                                        fodResourceStrings += "arsc: $s"
                                        if (Regex("^[a-zA-Z0-9_]+$").matches(s) &&
                                            (s.startsWith("config_") || s.contains("udfps", true) || s.contains("fod", true) || s.contains("hbm", true))
                                        ) {
                                            listOf("bool", "integer", "string", "array", "dimen").forEach { type ->
                                                discoveredKeys += type to s
                                            }
                                        }
                                    }
                                }
                            }
                            name.startsWith("res/") -> {
                                if (fodKeywordsRegex.containsMatchIn(name)) {
                                    fodResourceStrings += "resEntry: $name"
                                }
                                if (name.endsWith(".xml") && (fodKeywordsRegex.containsMatchIn(name) || name.contains("res/xml"))) {
                                    val data = zip.readBytes()
                                    val xmlStrings = extractStringsFromAndroidBinaryChunks(data)
                                    xmlStrings.filter { it.length in 2..120 && fodKeywordsRegex.containsMatchIn(it) }
                                        .distinct().take(12)
                                        .forEach { fodResourceStrings += "${name}: $it" }
                                }
                            }
                        }
                    }
                    zip.closeEntry()
                    entry = zip.nextEntry
                }
            }
        }

        return ParsedApkSignals(
            inferredTargetPackage = inferredTarget,
            manifestSignals = manifestSignals.distinct(),
            discoveredResourceKeys = discoveredKeys.distinct().take(80),
            fodResourceStrings = fodResourceStrings.distinct().take(60)
        )
    }

    /**
     * Walks Android binary XML / resources.arsc chunks extracting all RES_STRING_POOL_TYPE (0x0001) entries.
     * Supports both UTF-8 and UTF-16LE string pools reliably without native aapt.
     */
    internal fun extractStringsFromAndroidBinaryChunks(bytes: ByteArray): List<String> {
        if (bytes.size < 16) return emptyList()
        val results = mutableListOf<String>()
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)

        fun scanPools(start: Int, end: Int, depth: Int) {
            if (depth > 4) return
            var pos = start
            while (pos + 8 <= end) {
                val type = buf.getShort(pos).toInt() and 0xFFFF
                val headerSize = buf.getShort(pos + 2).toInt() and 0xFFFF
                val chunkSize = buf.getInt(pos + 4)
                if (chunkSize < 8 || headerSize < 8 || pos + chunkSize > end) break

                when (type) {
                    0x0001 -> { // RES_STRING_POOL_TYPE
                        if (pos + 28 <= end && headerSize >= 28) {
                            val stringCount = buf.getInt(pos + 8)
                            val flags = buf.getInt(pos + 16)
                            val stringsStart = buf.getInt(pos + 20)
                            val isUtf8 = (flags and 0x100) != 0
                            val tableBase = pos + headerSize
                            val poolDataBase = pos + stringsStart
                            if (stringCount in 1..40_000 &&
                                tableBase + stringCount * 4 <= pos + chunkSize &&
                                poolDataBase in pos until (pos + chunkSize)
                            ) {
                                for (i in 0 until stringCount) {
                                    val strOffset = buf.getInt(tableBase + i * 4)
                                    val absPos = poolDataBase + strOffset
                                    if (absPos !in poolDataBase until (pos + chunkSize)) continue
                                    val decoded = if (isUtf8) {
                                        decodeUtf8PoolString(bytes, absPos, pos + chunkSize)
                                    } else {
                                        decodeUtf16PoolString(bytes, absPos, pos + chunkSize)
                                    }
                                    if (decoded.isNotBlank()) results += decoded
                                }
                            }
                        }
                    }
                    0x0003, // RES_XML_TYPE
                    0x0002, // RES_TABLE_TYPE
                    0x0200 -> { // RES_TABLE_PACKAGE_TYPE
                        val childStart = pos + headerSize
                        if (childStart < pos + chunkSize) {
                            scanPools(childStart, pos + chunkSize, depth + 1)
                        }
                    }
                }
                pos += chunkSize
            }
        }

        scanPools(0, bytes.size, 0)
        return results
    }

    private fun decodeUtf8PoolString(bytes: ByteArray, offset: Int, limit: Int): String {
        var p = offset
        if (p >= limit) return ""
        val first = bytes[p++].toInt() and 0xFF
        if ((first and 0x80) != 0 && p < limit) p++
        if (p >= limit) return ""
        var byteLen = bytes[p++].toInt() and 0xFF
        if ((byteLen and 0x80) != 0 && p < limit) {
            byteLen = ((byteLen and 0x7F) shl 8) or (bytes[p++].toInt() and 0xFF)
        }
        if (byteLen <= 0 || p + byteLen > limit || byteLen > 2048) return ""
        return String(bytes, p, byteLen, Charsets.UTF_8)
    }

    private fun decodeUtf16PoolString(bytes: ByteArray, offset: Int, limit: Int): String {
        var p = offset
        if (p + 2 > limit) return ""
        var charLen = (bytes[p].toInt() and 0xFF) or ((bytes[p + 1].toInt() and 0xFF) shl 8)
        p += 2
        if ((charLen and 0x8000) != 0 && p + 2 <= limit) {
            val low = (bytes[p].toInt() and 0xFF) or ((bytes[p + 1].toInt() and 0xFF) shl 8)
            charLen = ((charLen and 0x7FFF) shl 16) or low
            p += 2
        }
        val byteLen = charLen * 2
        if (byteLen <= 0 || p + byteLen > limit || charLen > 1024) return ""
        return String(bytes, p, byteLen, Charsets.UTF_16LE)
    }

    @Suppress("DiscouragedApi")
    private fun resolvePackageResourceValues(
        pm: PackageManager,
        pkg: String,
        discoveredKeys: List<Pair<String, String>>
    ): List<String> {
        val out = mutableListOf<String>()
        val res: Resources = runCatching { pm.getResourcesForApplication(pkg) }.getOrNull() ?: return out
        val keysToCheck = (discoveredKeys + probeResourceSeeds).distinct()

        for ((type, name) in keysToCheck) {
            val id = runCatching { res.getIdentifier(name, type, pkg) }.getOrDefault(0)
            if (id == 0) continue
            val valueStr = when (type) {
                "bool" -> runCatching { res.getBoolean(id).toString() }.getOrNull()
                "integer" -> runCatching { res.getInteger(id).toString() }.getOrNull()
                "string" -> runCatching { res.getString(id) }.getOrNull()
                "dimen" -> runCatching { "${res.getDimension(id)}px" }.getOrNull()
                "array" -> runCatching {
                    val strArr = res.getStringArray(id)
                    if (strArr.any { it != null }) {
                        strArr.joinToString(", ", "[", "]")
                    } else {
                        res.getIntArray(id).joinToString(", ", "[", "]")
                    }
                }.getOrNull()
                else -> null
            }
            if (!valueStr.isNullOrBlank()) {
                out += "VALUE $type/$name = $valueStr"
            }
        }
        return out
    }

    private suspend fun discoverPropFilesProvenance(
        getpropAll: String,
        effectiveRoot: Boolean,
        limitations: MutableList<String>
    ): List<FileProvenanceArtifact> {
        val results = mutableListOf<FileProvenanceArtifact>()
        val propFiles = if (effectiveRoot) {
            ShellExecutor.exec(
                "find /system /system_ext /product /odm /vendor -maxdepth 4 -name '*.prop' 2>/dev/null | head -n 60",
                useRoot = true,
                timeoutMs = 5_000L
            ).stdout.lines().map { it.trim() }.filter { it.startsWith("/") }
        } else {
            listOf(
                "/system/build.prop",
                "/system_ext/etc/build.prop",
                "/product/etc/build.prop",
                "/vendor/build.prop",
                "/odm/etc/build.prop"
            ).filter { File(it).canRead() }
        }

        if (propFiles.isEmpty()) {
            if (!effectiveRoot) {
                limitations += ".prop file origin paths require root or readable build.prop."
            }
            return results
        }

        if (effectiveRoot) {
            val grepRes = ShellExecutor.exec(
                "grep -rnE 'fod|udfps|fingerprint|biometric|hbm|lhbm|phh|treble|disp_param|goodix|fp\\.' /system/build.prop /system_ext /product /vendor /odm --include='*.prop' 2>/dev/null | head -n 220",
                useRoot = true,
                timeoutMs = 6_000L
            )
            // Fallback busybox/toybox grep if `--include` isn't supported:
            val output = if (grepRes.isSuccess && grepRes.stdout.isNotBlank()) {
                grepRes.stdout
            } else {
                val safeFiles = propFiles.filter { !it.contains("'") }.joinToString(" ") { "'$it'" }
                if (safeFiles.isNotBlank()) {
                    ShellExecutor.exec(
                        "grep -niE 'fod|udfps|fingerprint|biometric|hbm|lhbm|phh|treble|disp_param|goodix|fp\\.' $safeFiles 2>/dev/null | head -n 220",
                        useRoot = true,
                        timeoutMs = 6_000L
                    ).stdout
                } else ""
            }

            val grouped = output.lineSequence()
                .filter { it.contains(":") && it.startsWith("/") }
                .groupBy { it.substringBefore(":") }

            grouped.entries.take(25).forEachIndexed { idx, (filePath, lines) ->
                val cleanLines = lines.map { it.substringAfter(":").trim() }.filter { it.isNotBlank() && !it.startsWith("#") }.distinct()
                if (cleanLines.isNotEmpty()) {
                    results += FileProvenanceArtifact(
                        id = "prov_prop_$idx",
                        category = "PROP_FILE",
                        filePath = filePath,
                        directory = filePath.substringBeforeLast('/'),
                        matchedSymbolOrKey = "${cleanLines.size} FOD/Display/Treble prop(s)",
                        importantContents = cleanLines.take(25)
                    )
                }
            }
        } else {
            propFiles.forEachIndexed { idx, filePath ->
                val matched = runCatching {
                    File(filePath).readLines().filter { fodKeywordsRegex.containsMatchIn(it) && !it.trim().startsWith("#") }
                }.getOrDefault(emptyList())
                if (matched.isNotEmpty()) {
                    results += FileProvenanceArtifact(
                        id = "prov_prop_$idx",
                        category = "PROP_FILE",
                        filePath = filePath,
                        directory = filePath.substringBeforeLast('/'),
                        matchedSymbolOrKey = "${matched.size} FOD/Display/Treble prop(s)",
                        importantContents = matched.take(25)
                    )
                }
            }
        }

        return results
    }

    private fun buildInitRcProvenance(initRcSnippets: String): List<FileProvenanceArtifact> {
        val grouped = initRcSnippets.lineSequence()
            .filter { it.startsWith("/") && it.contains(":") }
            .groupBy { it.substringBefore(":") }

        return grouped.entries.take(25).mapIndexed { idx, (path, lines) ->
            val clean = lines.map { it.substringAfter(":").trim() }.distinct()
            FileProvenanceArtifact(
                id = "prov_rc_$idx",
                category = "INIT_RC",
                filePath = path,
                directory = path.substringBeforeLast('/'),
                matchedSymbolOrKey = "${clean.size} FOD/HAL trigger(s)",
                importantContents = clean.take(25)
            )
        }
    }

    private fun extractDynamicHalKeywords(lshalOutput: String, vintfManifests: String): List<String> {
        val tokens = Regex("(goodix|focal|silead|egis|fpc|synaptics|xiaomi|oplus|samsung|google|qti|qcom|trustonic)", RegexOption.IGNORE_CASE)
            .findAll("$lshalOutput\n$vintfManifests")
            .map { it.value.lowercase() }
            .distinct()
            .toList()
        return tokens
    }

    private suspend fun discoverSystemXmlProvenance(
        effectiveRoot: Boolean,
        halTokens: List<String>
    ): List<FileProvenanceArtifact> {
        val results = mutableListOf<FileProvenanceArtifact>()
        val extraPattern = if (halTokens.isNotEmpty()) "|" + halTokens.joinToString("|") else ""
        val pattern = "fingerprint|biometric|udfps|fod|hbm|lhbm|displayconfig|high_brightness|disp_param$extraPattern"

        val xmlPaths = if (effectiveRoot) {
            ShellExecutor.exec(
                "find /system /system_ext /product /odm /vendor /apex -maxdepth 5 \\( -path '*/permissions/*' -o -path '*/sysconfig/*' -o -path '*/displayconfig/*' -o -path '*/vintf/*' \\) -name '*.xml' 2>/dev/null | head -n 180",
                useRoot = true,
                timeoutMs = 6_000L
            ).stdout.lines().map { it.trim() }.filter { it.startsWith("/") }
        } else {
            listOf("/system/etc/permissions", "/system_ext/etc/permissions", "/product/etc/permissions", "/vendor/etc/permissions")
                .flatMap { dir -> File(dir).listFiles()?.filter { it.isFile && it.canRead() && it.name.endsWith(".xml") }?.map { it.absolutePath }.orEmpty() }
        }

        val matchingPaths = xmlPaths.filter { path ->
            fodKeywordsRegex.containsMatchIn(path) || path.contains("displayconfig", true)
        }.take(25).toMutableList()

        // Also grep inside permission/sysconfig XMLs to find files whose filename isn't obvious
        if (effectiveRoot && xmlPaths.isNotEmpty()) {
            val safeXml = xmlPaths.filter { !it.contains("'") }.take(120).joinToString(" ") { "'$it'" }
            if (safeXml.isNotBlank()) {
                val grepOut = ShellExecutor.exec(
                    "grep -liE '$pattern' $safeXml 2>/dev/null | head -n 25",
                    useRoot = true,
                    timeoutMs = 5_000L
                ).stdout
                grepOut.lines().map { it.trim() }.filter { it.startsWith("/") }.forEach {
                    if (it !in matchingPaths) matchingPaths += it
                }
            }
        }

        matchingPaths.distinct().take(30).forEachIndexed { idx, path ->
            val readRes = ShellExecutor.readBinaryFile(path, effectiveRoot, maxBytes = 128 * 1024)
            val text = readRes.bytes?.toString(Charsets.UTF_8).orEmpty()
            if (text.isNotBlank()) {
                val important = text.lineSequence()
                    .map { it.trim() }
                    .filter {
                        it.isNotBlank() && (
                            fodKeywordsRegex.containsMatchIn(it) ||
                                it.contains("<feature", true) ||
                                it.contains("high-brightness", true) ||
                                it.contains("lux", true) ||
                                it.contains("hal", true) ||
                                it.contains("fqname", true)
                            )
                    }
                    .distinct()
                    .take(18)
                    .toList()
                if (important.isNotEmpty() || path.contains("displayconfig", true)) {
                    val cat = if (path.contains("displayconfig", true)) "DISPLAY_CONFIG" else "PERMISSIONS_XML"
                    results += FileProvenanceArtifact(
                        id = "prov_xml_$idx",
                        category = cat,
                        filePath = path,
                        directory = path.substringBeforeLast('/'),
                        matchedSymbolOrKey = path.substringAfterLast('/'),
                        importantContents = important.ifEmpty { listOf("XML size=${text.length} chars") }
                    )
                }
            }
        }

        return results
    }

    private suspend fun discoverSelinuxPolicyProvenance(effectiveRoot: Boolean): List<FileProvenanceArtifact> {
        if (!effectiveRoot) return emptyList()
        val filesOut = ShellExecutor.exec(
            "find /system /system_ext /product /odm /vendor -maxdepth 4 \\( -name '*.cil' -o -name '*contexts*' \\) 2>/dev/null | head -n 90",
            useRoot = true,
            timeoutMs = 5_000L
        ).stdout
        val files = filesOut.lines().map { it.trim() }.filter { it.startsWith("/") && !it.contains("'") }.take(60)
        if (files.isEmpty()) return emptyList()

        val safeList = files.joinToString(" ") { "'$it'" }
        val grepOut = ShellExecutor.exec(
            "grep -niE 'fingerprint|biometric|udfps|fod|hbm|lhbm|disp_param|goodix|touch_dev' $safeList 2>/dev/null | head -n 180",
            useRoot = true,
            timeoutMs = 6_000L
        ).stdout

        return grepOut.lineSequence()
            .filter { it.startsWith("/") && it.contains(":") }
            .groupBy { it.substringBefore(":") }
            .entries
            .take(20)
            .mapIndexed { idx, (filePath, lines) ->
                FileProvenanceArtifact(
                    id = "prov_selinux_$idx",
                    category = "SELINUX_POLICY",
                    filePath = filePath,
                    directory = filePath.substringBeforeLast('/'),
                    matchedSymbolOrKey = "${lines.size} SELinux policy/context rule(s)",
                    importantContents = lines.map { it.substringAfter(":").trim() }.distinct().take(18)
                )
            }
    }

    private suspend fun discoverSystemUiAndFrameworkProvenance(
        context: Context,
        effectiveRoot: Boolean
    ): List<FileProvenanceArtifact> {
        val out = mutableListOf<FileProvenanceArtifact>()
        val targetPaths = linkedSetOf<String>()

        // Resolve SystemUI APK path dynamically via PackageManager + pm path
        runCatching {
            val sysUiInfo = context.packageManager.getApplicationInfo("com.android.systemui", 0)
            if (!sysUiInfo.sourceDir.isNullOrBlank()) targetPaths += sysUiInfo.sourceDir
        }
        val sysUiPm = ShellExecutor.exec("pm path com.android.systemui", useRoot = effectiveRoot, timeoutMs = 3_000L).stdout
        sysUiPm.lineSequence()
            .filter { it.startsWith("package:") }
            .map { it.removePrefix("package:").trim() }
            .forEach { targetPaths += it }

        if (effectiveRoot) {
            ShellExecutor.exec(
                "ls -1 /system/framework/services.jar /system/framework/framework-res.apk /system_ext/priv-app/*SystemUI*/*.apk /system/priv-app/*SystemUI*/*.apk /apex/*biometric*/javalib/*.jar /apex/*biometric*/bin/* 2>/dev/null",
                useRoot = true,
                timeoutMs = 4_000L
            ).stdout.lines().map { it.trim() }.filter { it.startsWith("/") }.forEach { targetPaths += it }
        }

        targetPaths.take(10).forEachIndexed { idx, path ->
            val contents = mutableListOf<String>()
            if (path.endsWith(".apk")) {
                val readRes = ShellExecutor.readBinaryFile(path, effectiveRoot, maxBytes = 8 * 1024 * 1024)
                if (readRes.bytes != null) {
                    val parsed = parseApkBinaryFodDetails(readRes.bytes)
                    contents += parsed.fodResourceStrings.take(15)
                }
                if (path.contains("SystemUI", true)) {
                    contents += resolvePackageResourceValues(context.packageManager, "com.android.systemui", emptyList()).take(15)
                }
            }
            // Scan SystemUI / services.jar DEX string hints quickly if readable
            if ((path.endsWith(".apk") || path.endsWith(".jar")) && (path.contains("SystemUI", true) || path.contains("services.jar", true))) {
                val readRes = ShellExecutor.readBinaryFile(path, effectiveRoot, maxBytes = 8 * 1024 * 1024)
                if (readRes.bytes != null) {
                    val hints = extractStringsHintsFromArchive(readRes.bytes)
                    contents += hints.take(15)
                }
            }

            out += FileProvenanceArtifact(
                id = "prov_sysfw_$idx",
                category = "SYSTEMUI_FRAMEWORK",
                filePath = path,
                directory = path.substringBeforeLast('/'),
                matchedSymbolOrKey = path.substringAfterLast('/'),
                importantContents = contents.distinct().ifEmpty { listOf("Active runtime module at $path") }.take(25)
            )
        }
        return out
    }

    private fun extractStringsHintsFromArchive(bytes: ByteArray): List<String> {
        val hooks = listOf(
            "UdfpsController", "UdfpsDisplayMode", "UdfpsView", "extCmd", "onFingerDown",
            "IXiaomiFingerprint", "IOplusBiometricsFingerprint", "IGoogleFingerprint",
            "setHbm", "lhbm", "disp_param", "fod_status", "PhhFod"
        )
        val found = mutableListOf<String>()
        runCatching {
            ZipInputStream(ByteArrayInputStream(bytes)).use { zip ->
                var entry = zip.nextEntry
                while (entry != null) {
                    val n = entry.name
                    if (!entry.isDirectory && (n.endsWith(".xml") && fodKeywordsRegex.containsMatchIn(n))) {
                        found += "zipEntry: $n"
                    } else if (!entry.isDirectory && n == "classes.dex") {
                        val dexBytes = zip.readBytes()
                        val text = String(dexBytes, Charsets.ISO_8859_1)
                        hooks.forEach { h ->
                            if (text.contains(h)) found += "dexClass/Symbol: $h"
                        }
                    }
                    zip.closeEntry()
                    entry = zip.nextEntry
                }
            }
        }
        return found.distinct()
    }

    fun serializeOverlayDeepInspect(list: List<OverlayDeepInspection>): String = buildString {
        appendLine("=== DEEP OVERLAY INSPECTIONS (${list.size}) ===")
        list.forEach { ov ->
            appendLine("OVERLAY: ${ov.packageName}")
            appendLine("  ENABLED=${ov.isEnabled} | STATIC=${ov.isStatic} | PRIORITY=${ov.priority} | TARGET=${ov.targetPackage}")
            appendLine("  APK_PATH=${ov.apkPath}")
            appendLine("  DIRECTORY=${ov.directory}")
            ov.manifestSummary.forEach { appendLine("  MANIFEST: $it") }
            ov.fodConfigEntries.forEach { appendLine("  CONTENT: $it") }
            appendLine()
        }
    }

    fun serializeFileProvenanceIndex(list: List<FileProvenanceArtifact>): String = buildString {
        appendLine("=== DYNAMIC FILE PROVENANCE INDEX (${list.size}) ===")
        list.forEach { item ->
            appendLine("FILE: [${item.category}] ${item.filePath}")
            appendLine("  DIRECTORY=${item.directory}")
            appendLine("  KEY=${item.matchedSymbolOrKey}")
            item.importantContents.forEach { appendLine("  DETAIL: $it") }
            if (item.accessNote != null) appendLine("  NOTE: ${item.accessNote}")
            appendLine()
        }
    }
}
