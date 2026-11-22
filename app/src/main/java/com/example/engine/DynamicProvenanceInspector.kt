package com.example.engine

import android.content.Context
import android.content.pm.PackageManager
import android.content.res.Resources
import com.example.model.DexSourceExtract
import com.example.model.FileProvenanceArtifact
import com.example.model.LiveProcessMapRecord
import com.example.model.OverlayDeepInspection
import java.io.ByteArrayInputStream
import java.io.File
import java.util.zip.ZipInputStream

data class DynamicProvenanceBundle(
    val overlayInspections: List<OverlayDeepInspection>,
    val fileProvenance: List<FileProvenanceArtifact>,
    val dexSourceExtracts: List<DexSourceExtract>,
    val overlayDeepInspectText: String,
    val fileProvenanceIndexText: String,
    val dexSourceExtractText: String,
    val filteredNonFodOverlayCount: Int = 0
)

object DynamicProvenanceInspector {

    private val fodKeywordsRegex = Regex(
        "(fod|udfps|fingerprint|biometric|hbm|lhbm|dimlayer|doze_brightness|displayblanksafterdoze|dozeafterscreenoff|burn_in|illumination|optical|ultrasonic|goodix|fpc|silead|focal|egis|synaptics|disp_param|touch_dev|xiaomi\\.fingerprint|oplus\\.biometrics|phh\\.fod|treble)",
        RegexOption.IGNORE_CASE
    )

    private val coreBiometricOverlayTargets = setOf(
        "android",
        "com.android.systemui",
        "com.android.settings",
        "com.android.server.biometrics",
        "com.android.providers.settings"
    )

    // Well-known AOSP / OEM / Treble resource keys checked via Resources.getIdentifier & cmd overlay lookup
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
        accessLimitations: MutableList<String>,
        procLiveMaps: List<LiveProcessMapRecord> = emptyList()
    ): DynamicProvenanceBundle {
        val provenance = mutableListOf<FileProvenanceArtifact>()

        // 1. FIRST: Discover SystemUI / Framework / Services / Biometric APEX APK/JAR/VDEX containers & decode Dalvik bytecode + 0x7f.. R.id maps!
        val (sysFwProv, dexExtracts) = discoverSystemUiAndFrameworkProvenance(
            context = context,
            effectiveRoot = effectiveRoot,
            procLiveMaps = procLiveMaps
        )

        // Exact resource keys actually consumed inside FOD/UDFPS/Biometric Dalvik bytecode
        val bytecodeConsumedResKeys = dexExtracts
            .flatMap { it.resolvedResourceKeys }
            .filter { !it.startsWith("0x") }
            .toSet()

        // 2. Inspect overlays & prove strictly against bytecode R.id keys + cmd overlay lookup + /proc/<pid>/maps (ZERO false positives!)
        val (strictOverlays, filteredOverlayCount) = inspectOverlays(
            context = context,
            dumpsysOverlayList = dumpsysOverlayList,
            installedPackages = installedOverlayPackages,
            effectiveRoot = effectiveRoot,
            procLiveMaps = procLiveMaps,
            bytecodeConsumedResKeys = bytecodeConsumedResKeys
        )

        strictOverlays.forEachIndexed { idx, ov ->
            val contents = mutableListOf<String>()
            contents += "strictProven=${ov.isStrictProvenFod} | fodScore=${ov.fodRelevanceScore} | liveMapped=${ov.provenInLiveMaps} | target=${ov.targetPackage.ifBlank { "UNKNOWN" }} | enabled=${ov.isEnabled} | static=${ov.isStatic} | prio=${ov.priority}"
            if (ov.bytecodeMatchedResourceKeys.isNotEmpty()) {
                contents += "bytecodeMatchedKeys=${ov.bytecodeMatchedResourceKeys.joinToString("; ")}"
            }
            if (ov.lookupWinners.isNotEmpty()) {
                contents += "lookupWinners=${ov.lookupWinners.joinToString("; ")}"
            }
            contents.addAll(ov.decodedArscEntries.take(20))
            contents.addAll(ov.manifestSummary.take(8))
            contents.addAll(ov.fodConfigEntries.take(20))
            provenance += FileProvenanceArtifact(
                id = "prov_ov_${idx}_${ov.packageName.hashCode()}",
                category = "OVERLAY_APK",
                filePath = ov.apkPath,
                directory = ov.directory,
                matchedSymbolOrKey = ov.packageName,
                importantContents = contents.distinct().take(40),
                accessNote = if (ov.apkPath == "UNKNOWN") "APK path unresolved on device" else null
            )
        }

        // 3. Dynamic .prop files provenance scan
        provenance += discoverPropFilesProvenance(getpropAll, effectiveRoot, accessLimitations)

        // 4. Parse init.rc provenance directly from dynamic grep + file grouping
        provenance += buildInitRcProvenance(initRcSnippets)

        // 5. Dynamic XML discovery (permissions, sysconfig, displayconfig, vintf)
        val extraHalKeywords = extractDynamicHalKeywords(lshalOutput, vintfManifests)
        provenance += discoverSystemXmlProvenance(effectiveRoot, extraHalKeywords)

        // 6. Dynamic SELinux policy files (.cil / contexts / policy)
        provenance += discoverSelinuxPolicyProvenance(effectiveRoot)

        // 7. SystemUI / Framework bytecode artifacts
        provenance += sysFwProv

        val distinctProvenance = provenance.distinctBy { "${it.category}::${it.filePath}::${it.matchedSymbolOrKey}" }
        val overlayText = serializeOverlayDeepInspect(strictOverlays, filteredOverlayCount)
        val provenanceText = serializeFileProvenanceIndex(distinctProvenance)
        val dexText = serializeDexSourceExtracts(dexExtracts)

        return DynamicProvenanceBundle(
            overlayInspections = strictOverlays,
            fileProvenance = distinctProvenance,
            dexSourceExtracts = dexExtracts,
            overlayDeepInspectText = overlayText,
            fileProvenanceIndexText = provenanceText,
            dexSourceExtractText = dexText,
            filteredNonFodOverlayCount = filteredOverlayCount
        )
    }

    private suspend fun inspectOverlays(
        context: Context,
        dumpsysOverlayList: String,
        installedPackages: List<String>,
        effectiveRoot: Boolean,
        procLiveMaps: List<LiveProcessMapRecord>,
        bytecodeConsumedResKeys: Set<String>
    ): Pair<List<OverlayDeepInspection>, Int> {
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

        // Discover ALL overlay APKs on overlay partitions regardless of package name!
        val partitionOverlayApks = if (effectiveRoot) {
            ShellExecutor.exec(
                "find /system /system_ext /product /vendor /odm /apex -maxdepth 5 \\( -path '*/overlay/*' -o -iname '*overlay*.apk' -o -iname '*rro*.apk' -o -iname '*udfps*.apk' -o -iname '*fod*.apk' -o -iname '*treble*.apk' \\) -iname '*.apk' 2>/dev/null | sort -u | head -n 180",
                useRoot = true,
                timeoutMs = 7_000L
            ).stdout.lines().map { it.trim() }.filter { it.startsWith("/") }
        } else {
            emptyList()
        }

        // Content-first discovery: collect ALL enabled overlays + overlays targeting core/biometric pkgs + all installed overlay pkgs
        val candidatePackages = linkedSetOf<String>()
        stateMap.keys.forEach { pkg -> candidatePackages += pkg }
        dumpMap.values.forEach { info ->
            if (info.isEnabled || info.isStatic || info.targetPackage in coreBiometricOverlayTargets || fodKeywordsRegex.containsMatchIn(info.packageName)) {
                candidatePackages += info.packageName
            }
        }
        installedPackages.forEach { candidatePackages += it }

        // Build fast lookup sets from live /proc/<pid>/maps (SystemUI, system_server, surfaceflinger, HALs)
        val liveMappedApks = procLiveMaps.flatMap { it.mappedApks }.toHashSet()
        val liveMappedLower = liveMappedApks.map { it.lowercase() }.toHashSet()

        // Also map any partition APK whose filename isn't yet represented by package name
        val knownApkPaths = dumpMap.values.mapNotNull { it.baseCodePath.takeIf { p -> p.startsWith("/") } }.toHashSet()
        val unmappedPartitionApks = partitionOverlayApks.filter { it !in knownApkPaths }.take(40)

        val pm = context.packageManager
        val rawInspections = mutableListOf<OverlayDeepInspection>()
        val discoveredDynamicKeys = linkedSetOf<Pair<String, String>>()

        // Inspect all registered candidate packages (generous cap of 150 so non-keyword FOD overlays are never skipped)
        for (pkg in candidatePackages.take(150)) {
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

            // Fallback 2: `pm path <pkg>` (only if root or small remainder, avoided if already mapped)
            if (apkPath.isBlank() && (enabled || fodKeywordsRegex.containsMatchIn(pkg))) {
                val pmOut = ShellExecutor.exec("pm path '$pkg'", useRoot = effectiveRoot, timeoutMs = 2_500L).stdout
                apkPath = pmOut.lineSequence()
                    .firstOrNull { it.startsWith("package:") }
                    ?.removePrefix("package:")
                    ?.trim()
                    .orEmpty()
            }

            // Fallback 3: Partition APK path matching
            if (apkPath.isBlank()) {
                val shortToken = pkg.substringAfterLast('.').lowercase()
                apkPath = partitionOverlayApks.firstOrNull { path ->
                    path.contains(pkg, ignoreCase = true) || (shortToken.length >= 4 && path.contains(shortToken, ignoreCase = true))
                }.orEmpty()
            }

            val finalApkPath = apkPath.ifBlank { "UNKNOWN" }
            val directory = if (finalApkPath.contains("/")) finalApkPath.substringBeforeLast('/') else "UNKNOWN"

            val manifestSummary = mutableListOf<String>()
            val configEntries = mutableListOf<String>()
            val decodedArsc = mutableListOf<String>()
            val pseudoXmlChunks = mutableListOf<String>()

            if (finalApkPath != "UNKNOWN") {
                val readRes = ShellExecutor.readBinaryFile(finalApkPath, effectiveRoot, maxBytes = 6 * 1024 * 1024)
                if (readRes.bytes != null) {
                    val apkParsed = parseApkBinaryFodDetails(readRes.bytes)
                    if (targetPkg.isBlank() && apkParsed.inferredTargetPackage.isNotBlank()) {
                        targetPkg = apkParsed.inferredTargetPackage
                    }
                    manifestSummary += apkParsed.manifestSignals
                    configEntries += apkParsed.fodResourceStrings
                    decodedArsc += apkParsed.decodedArscEntries
                    if (apkParsed.pseudoXmlSource.isNotBlank()) {
                        pseudoXmlChunks += apkParsed.pseudoXmlSource
                    }
                    apkParsed.discoveredResourceKeys.forEach { discoveredDynamicKeys += it }

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

            if (decodedArsc.isEmpty() && configEntries.isEmpty()) {
                configEntries += resolvePackageResourceValues(pm, pkg, emptyList())
            }

            if (targetPkg.isNotBlank() && enabled) {
                val manifestTag = "Overrides targetPackage=$targetPkg"
                if (manifestTag !in manifestSummary) manifestSummary += manifestTag
            }

            val provenLive = finalApkPath != "UNKNOWN" && (
                finalApkPath in liveMappedApks ||
                    liveMappedLower.any { it.contains(finalApkPath.lowercase()) || (directory != "UNKNOWN" && directory.length > 8 && it.contains(directory.lowercase())) }
                )

            rawInspections += OverlayDeepInspection(
                packageName = pkg,
                targetPackage = targetPkg,
                apkPath = finalApkPath,
                directory = directory,
                isEnabled = enabled,
                isStatic = isStatic,
                priority = priority,
                manifestSummary = manifestSummary.distinct().take(16),
                fodConfigEntries = configEntries.distinct().take(50),
                rawDumpNote = dumpInfo?.rawSnippet.orEmpty(),
                fodRelevanceScore = 0, // computed after runtime cmd overlay lookup check
                provenInLiveMaps = provenLive,
                lookupWinners = emptyList(),
                pseudoXmlSource = pseudoXmlChunks.joinToString("\n").take(3500),
                decodedArscEntries = decodedArsc.distinct().take(60)
            )
        }

        // Also inspect any partition RRO APK that wasn't even registered in dumpsys/cmd overlay list (e.g. unmounted or auto-generated file discovery)
        for (rawPath in unmappedPartitionApks) {
            if (rawInspections.any { it.apkPath == rawPath }) continue
            val readRes = ShellExecutor.readBinaryFile(rawPath, effectiveRoot, maxBytes = 6 * 1024 * 1024)
            val bytes = readRes.bytes ?: continue
            val parsed = parseApkBinaryFodDetails(bytes)
            // Keep unmapped partition APK only if decoded ARSC/XML has actual FOD/biometric/config content
            if (parsed.decodedArscEntries.isEmpty() && parsed.fodResourceStrings.isEmpty()) continue
            val provenLive = rawPath in liveMappedApks || liveMappedLower.any { it.contains(rawPath.lowercase()) }
            rawInspections += OverlayDeepInspection(
                packageName = rawPath.substringAfterLast('/').removeSuffix(".apk"),
                targetPackage = parsed.inferredTargetPackage,
                apkPath = rawPath,
                directory = rawPath.substringBeforeLast('/'),
                isEnabled = provenLive,
                isStatic = rawPath.contains("auto_generated", true),
                priority = 0,
                manifestSummary = parsed.manifestSignals.distinct().take(16),
                fodConfigEntries = parsed.fodResourceStrings.distinct().take(50),
                rawDumpNote = "Discovered directly on partition scan",
                fodRelevanceScore = 0,
                provenInLiveMaps = provenLive,
                lookupWinners = emptyList(),
                pseudoXmlSource = parsed.pseudoXmlSource.take(3500),
                decodedArscEntries = parsed.decodedArscEntries.distinct().take(60)
            )
        }

        // Build lookup probes starting from exact Dalvik bytecode R.id keys + fallback seeds
        val bytecodeLookupPairs = bytecodeConsumedResKeys.mapNotNull { fullKey ->
            val shortKey = fullKey.substringAfter(':', fullKey)
            val type = shortKey.substringBefore('/', "")
            val name = shortKey.substringAfter('/', "")
            if (type.isNotBlank() && name.isNotBlank()) type to name else null
        }

        val lookupResults = if (effectiveRoot) {
            queryOverlayLookupWinners((bytecodeLookupPairs + discoveredDynamicKeys).distinct())
        } else {
            emptyMap()
        }

        val bytecodeShortKeys = bytecodeLookupPairs.map { "${it.first}/${it.second}" }.toSet()
        val hasVerificationContext = effectiveRoot || bytecodeShortKeys.isNotEmpty()

        // Compute strict causal proof & filter out all generic/false-positive overlays!
        val scored = rawInspections.map { ov ->
            val matchedLookups = lookupResults.entries
                .filter { (_, output) ->
                    output.contains(ov.packageName, ignoreCase = true) ||
                        (ov.apkPath != "UNKNOWN" && output.contains(ov.apkPath, ignoreCase = true))
                }
                .map { "${it.key} -> ${it.value.take(140)}" }

            val matchedBytecodeKeys = ov.decodedArscEntries.mapNotNull { entry ->
                // format: "ARSC bool/config_supportsUdfps = true"
                val typeAndKey = entry.removePrefix("ARSC ").substringBefore(" =").trim()
                val shortName = typeAndKey.substringAfter('/', "")
                val matchesBytecode = typeAndKey in bytecodeShortKeys ||
                    bytecodeConsumedResKeys.any { it.endsWith("/$shortName") }
                if (matchesBytecode) typeAndKey else null
            }.distinct()

            val fodArscCount = ov.decodedArscEntries.count { fodKeywordsRegex.containsMatchIn(it) }
            val fodConfigCount = ov.fodConfigEntries.count { fodKeywordsRegex.containsMatchIn(it) }

            val isStrictProven = when {
                matchedLookups.isNotEmpty() -> true
                matchedBytecodeKeys.isNotEmpty() && (ov.isEnabled || ov.isStatic || ov.provenInLiveMaps) -> true
                !hasVerificationContext && ov.provenInLiveMaps && (fodArscCount > 0 || fodConfigCount > 0) -> true
                // Allow explicitly FOD/UDFPS ARSC overlays loaded in /proc/<pid>/maps if lookup didn't cover vendor-specific key names
                ov.provenInLiveMaps && fodArscCount > 0 && ov.targetPackage in coreBiometricOverlayTargets -> true
                else -> false
            }

            val baseScore = computeFodOverlayScore(
                ov = ov,
                matchedLookups = matchedLookups
            )
            val totalScore = baseScore + (matchedBytecodeKeys.size * 55)

            ov.copy(
                fodRelevanceScore = totalScore,
                lookupWinners = matchedLookups,
                bytecodeMatchedResourceKeys = matchedBytecodeKeys,
                isStrictProvenFod = isStrictProven
            )
        }

        val strictlyProven = scored
            .filter { it.isStrictProvenFod }
            .sortedWith(
                compareByDescending<OverlayDeepInspection> { it.fodRelevanceScore }
                    .thenByDescending { it.lookupWinners.size }
                    .thenByDescending { it.bytecodeMatchedResourceKeys.size }
                    .thenByDescending { it.provenInLiveMaps }
                    .thenByDescending { it.isEnabled }
                    .thenBy { it.packageName }
            )
            .take(35)

        val rejectedCount = (scored.size - strictlyProven.size).coerceAtLeast(0)
        return strictlyProven to rejectedCount
    }

    internal fun computeFodOverlayScore(
        ov: OverlayDeepInspection,
        matchedLookups: List<String> = ov.lookupWinners
    ): Int {
        var score = 0
        val fodArscCount = ov.decodedArscEntries.count { fodKeywordsRegex.containsMatchIn(it) }
        val nonFodConfigArsc = (ov.decodedArscEntries.size - fodArscCount).coerceAtLeast(0)
        val fodEntryCount = ov.fodConfigEntries.count { fodKeywordsRegex.containsMatchIn(it) }
        val hasXmlFod = ov.pseudoXmlSource.isNotBlank() && fodKeywordsRegex.containsMatchIn(ov.pseudoXmlSource)

        score += minOf(ov.bytecodeMatchedResourceKeys.size * 55, 220)
        score += minOf(fodArscCount * 40, 200)
        score += minOf(fodEntryCount * 20, 80)
        if (nonFodConfigArsc > 0 && fodArscCount == 0) score += 10
        if (hasXmlFod) score += 30
        if (matchedLookups.isNotEmpty()) score += 60
        if (ov.provenInLiveMaps) score += 45

        val hasRealFodSignal = ov.bytecodeMatchedResourceKeys.isNotEmpty() || fodArscCount > 0 || fodEntryCount > 0 || hasXmlFod || matchedLookups.isNotEmpty()
        if (hasRealFodSignal) {
            if (ov.isEnabled) score += 25
            if (ov.targetPackage in coreBiometricOverlayTargets) score += 15
        } else {
            if (ov.isEnabled) score += 5
            if (ov.provenInLiveMaps) score += 10
        }
        return score
    }

    private suspend fun queryOverlayLookupWinners(
        discoveredKeys: List<Pair<String, String>>
    ): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        val keyCandidates = (discoveredKeys + probeResourceSeeds)
            .filter { (type, name) ->
                type in setOf("bool", "integer", "string", "array", "dimen") &&
                    Regex("^[a-zA-Z0-9_]+$").matches(name) &&
                    (fodKeywordsRegex.containsMatchIn(name) || name.startsWith("config_"))
            }
            .distinct()
            .take(18)

        if (keyCandidates.isEmpty()) return out

        val targets = listOf("android", "com.android.systemui")
        val pairsToQuery = mutableListOf<Pair<String, String>>()
        for (target in targets) {
            for ((type, name) in keyCandidates.take(12)) {
                pairsToQuery += target to "$target:$type/$name"
            }
        }

        // Run in chunks of 12 lookups so commands never time out
        for (chunk in pairsToQuery.chunked(12)) {
            val script = chunk.joinToString("; ") { (target, fq) ->
                "echo \"KEY=$target|$fq\"; cmd overlay lookup --verbose $target $fq 2>/dev/null || cmd overlay lookup $target $fq 2>/dev/null"
            }
            val res = ShellExecutor.exec(script, useRoot = true, timeoutMs = 8_000L)
            if (res.stdout.isBlank()) continue

            var curKey = ""
            val buf = StringBuilder()
            fun flush() {
                if (curKey.isNotBlank() && buf.isNotBlank()) {
                    out[curKey] = buf.toString().lines().take(4).joinToString(" | ").trim()
                }
                buf.clear()
            }
            for (line in res.stdout.lineSequence()) {
                val t = line.trim()
                if (t.startsWith("KEY=")) {
                    flush()
                    curKey = t.removePrefix("KEY=").trim()
                } else if (t.isNotBlank() && !t.startsWith("Error", true)) {
                    buf.appendLine(t)
                }
            }
            flush()
        }
        return out
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
        val fodResourceStrings: List<String>,
        val decodedArscEntries: List<String> = emptyList(),
        val pseudoXmlSource: String = ""
    )

    internal fun parseApkBinaryFodDetails(apkBytes: ByteArray): ParsedApkSignals {
        val manifestSignals = mutableListOf<String>()
        val discoveredKeys = mutableListOf<Pair<String, String>>()
        val fodResourceStrings = mutableListOf<String>()
        val decodedArscEntries = mutableListOf<String>()
        val xmlBlocks = mutableListOf<String>()
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
                                val pseudo = BinarySourceDecoder.decodeBinaryXmlToPseudoXml(data, maxLines = 45)
                                if (pseudo.isNotBlank()) {
                                    xmlBlocks += "// $name\n$pseudo"
                                    val targetMatch = Regex("""targetPackage="([^"]+)"""").find(pseudo)
                                    if (targetMatch != null && inferredTarget.isBlank()) {
                                        inferredTarget = targetMatch.groupValues[1]
                                    }
                                }
                                val poolStrings = extractStringsFromAndroidBinaryChunks(data)
                                if (inferredTarget.isBlank()) {
                                    inferredTarget = poolStrings.firstOrNull {
                                        it in coreBiometricOverlayTargets
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
                                // Full RES_TABLE_TYPE decoding (key/type/value)
                                val arscDecoded = BinarySourceDecoder.decodeArscResourceEntries(data, maxFodEntries = 100)
                                arscDecoded.allFodOrConfigEntries.forEach { rec ->
                                    val formatted = "ARSC ${rec.typeName}/${rec.keyName} = ${rec.valueText}"
                                    decodedArscEntries += formatted
                                    if (fodKeywordsRegex.containsMatchIn(rec.keyName) || fodKeywordsRegex.containsMatchIn(rec.valueText)) {
                                        fodResourceStrings += formatted
                                    }
                                }
                                discoveredKeys += arscDecoded.discoveredResourceKeys

                                // Fallback string pool scan (always captures raw string tokens even on minimal synthetic test chunks)
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
                                if (name.endsWith(".xml") && (fodKeywordsRegex.containsMatchIn(name) || name.contains("res/xml") || name.contains("res/values"))) {
                                    val data = zip.readBytes()
                                    val pseudoXml = BinarySourceDecoder.decodeBinaryXmlToPseudoXml(data, maxLines = 55)
                                    if (pseudoXml.isNotBlank() && (fodKeywordsRegex.containsMatchIn(pseudoXml) || fodKeywordsRegex.containsMatchIn(name))) {
                                        xmlBlocks += "// $name\n$pseudoXml"
                                    }
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
            discoveredResourceKeys = discoveredKeys.distinct().take(100),
            fodResourceStrings = fodResourceStrings.distinct().take(70),
            decodedArscEntries = decodedArscEntries.distinct().take(80),
            pseudoXmlSource = xmlBlocks.joinToString("\n\n").take(3800)
        )
    }

    internal fun extractStringsFromAndroidBinaryChunks(bytes: ByteArray): List<String> {
        if (bytes.size < 16) return emptyList()
        val results = mutableListOf<String>()
        val buf = java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN)

        fun scanPools(start: Int, end: Int, depth: Int) {
            if (depth > 4) return
            var pos = start
            while (pos + 8 <= end) {
                val type = buf.getShort(pos).toInt() and 0xFFFF
                val headerSize = buf.getShort(pos + 2).toInt() and 0xFFFF
                val chunkSize = buf.getInt(pos + 4)
                if (chunkSize < 8 || headerSize < 8 || pos + chunkSize > end) break

                when (type) {
                    0x0001 -> {
                        results += BinarySourceDecoder.parseStringPool(bytes, pos, pos + chunkSize)
                            .filter { it.isNotBlank() }
                    }
                    0x0003,
                    0x0002,
                    0x0200 -> {
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
                "find /system /system_ext /product /odm /vendor -maxdepth 4 -name '*.prop' 2>/dev/null | head -n 70",
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
            val safeFiles = propFiles.filter { !it.contains("'") }.joinToString(" ") { "'$it'" }
            val output = if (safeFiles.isNotBlank()) {
                ShellExecutor.exec(
                    "grep -niE 'fod|udfps|fingerprint|biometric|hbm|lhbm|phh|treble|disp_param|goodix|fp\\.' $safeFiles 2>/dev/null | head -n 260",
                    useRoot = true,
                    timeoutMs = 6_000L
                ).stdout
            } else ""

            val grouped = output.lineSequence()
                .filter { it.contains(":") && it.startsWith("/") }
                .groupBy { it.substringBefore(":") }

            grouped.entries.take(30).forEachIndexed { idx, (filePath, lines) ->
                val cleanLines = lines.map { it.substringAfter(":").trim() }.filter { it.isNotBlank() && !it.startsWith("#") }.distinct()
                if (cleanLines.isNotEmpty()) {
                    results += FileProvenanceArtifact(
                        id = "prov_prop_$idx",
                        category = "PROP_FILE",
                        filePath = filePath,
                        directory = filePath.substringBeforeLast('/'),
                        matchedSymbolOrKey = "${cleanLines.size} FOD/Display/Treble prop(s)",
                        importantContents = cleanLines.take(30)
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

        return grouped.entries.take(30).mapIndexed { idx, (path, lines) ->
            val clean = lines.map { it.substringAfter(":").trim() }.distinct()
            FileProvenanceArtifact(
                id = "prov_rc_$idx",
                category = "INIT_RC",
                filePath = path,
                directory = path.substringBeforeLast('/'),
                matchedSymbolOrKey = "${clean.size} FOD/HAL trigger(s)",
                importantContents = clean.take(30)
            )
        }
    }

    private fun extractDynamicHalKeywords(lshalOutput: String, vintfManifests: String): List<String> {
        return Regex("(goodix|focal|silead|egis|fpc|synaptics|xiaomi|oplus|samsung|google|qti|qcom|trustonic)", RegexOption.IGNORE_CASE)
            .findAll("$lshalOutput\n$vintfManifests")
            .map { it.value.lowercase() }
            .distinct()
            .toList()
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
                "find /system /system_ext /product /odm /vendor /apex -maxdepth 5 \\( -path '*/permissions/*' -o -path '*/sysconfig/*' -o -path '*/displayconfig/*' -o -path '*/vintf/*' \\) -name '*.xml' 2>/dev/null | head -n 200",
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

        if (effectiveRoot && xmlPaths.isNotEmpty()) {
            val safeXml = xmlPaths.filter { !it.contains("'") }.take(130).joinToString(" ") { "'$it'" }
            if (safeXml.isNotBlank()) {
                val grepOut = ShellExecutor.exec(
                    "grep -liE '$pattern' $safeXml 2>/dev/null | head -n 30",
                    useRoot = true,
                    timeoutMs = 5_000L
                ).stdout
                grepOut.lines().map { it.trim() }.filter { it.startsWith("/") }.forEach {
                    if (it !in matchingPaths) matchingPaths += it
                }
            }
        }

        matchingPaths.distinct().take(35).forEachIndexed { idx, path ->
            val readRes = ShellExecutor.readBinaryFile(path, effectiveRoot, maxBytes = 128 * 1024)
            val text = readRes.bytes?.let { bytes ->
                if (bytes.size >= 4 && bytes[0] == 0x03.toByte() && bytes[1] == 0x00.toByte()) {
                    BinarySourceDecoder.decodeBinaryXmlToPseudoXml(bytes, maxLines = 40)
                } else {
                    bytes.toString(Charsets.UTF_8)
                }
            }.orEmpty()
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
                    .take(20)
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
            "find /system /system_ext /product /odm /vendor -maxdepth 4 \\( -name '*.cil' -o -name '*contexts*' \\) 2>/dev/null | head -n 100",
            useRoot = true,
            timeoutMs = 5_000L
        ).stdout
        val files = filesOut.lines().map { it.trim() }.filter { it.startsWith("/") && !it.contains("'") }.take(70)
        if (files.isEmpty()) return emptyList()

        val safeList = files.joinToString(" ") { "'$it'" }
        val grepOut = ShellExecutor.exec(
            "grep -niE 'fingerprint|biometric|udfps|fod|hbm|lhbm|disp_param|goodix|touch_dev' $safeList 2>/dev/null | head -n 220",
            useRoot = true,
            timeoutMs = 6_000L
        ).stdout

        return grepOut.lineSequence()
            .filter { it.startsWith("/") && it.contains(":") }
            .groupBy { it.substringBefore(":") }
            .entries
            .take(25)
            .mapIndexed { idx, (filePath, lines) ->
                FileProvenanceArtifact(
                    id = "prov_selinux_$idx",
                    category = "SELINUX_POLICY",
                    filePath = filePath,
                    directory = filePath.substringBeforeLast('/'),
                    matchedSymbolOrKey = "${lines.size} SELinux policy/context rule(s)",
                    importantContents = lines.map { it.substringAfter(":").trim() }.distinct().take(20)
                )
            }
    }

    private suspend fun discoverSystemUiAndFrameworkProvenance(
        context: Context,
        effectiveRoot: Boolean,
        procLiveMaps: List<LiveProcessMapRecord>
    ): Pair<List<FileProvenanceArtifact>, List<DexSourceExtract>> {
        val out = mutableListOf<FileProvenanceArtifact>()
        val dexExtracts = mutableListOf<DexSourceExtract>()
        val targetPaths = linkedSetOf<String>()

        runCatching {
            val sysUiInfo = context.packageManager.getApplicationInfo("com.android.systemui", 0)
            if (!sysUiInfo.sourceDir.isNullOrBlank()) targetPaths += sysUiInfo.sourceDir
        }
        val sysUiPm = ShellExecutor.exec("pm path com.android.systemui", useRoot = effectiveRoot, timeoutMs = 3_000L).stdout
        sysUiPm.lineSequence()
            .filter { it.startsWith("package:") }
            .map { it.removePrefix("package:").trim() }
            .forEach { targetPaths += it }

        // Build 0x7f...... / 0x01...... ARSC ID lookup maps from framework-res.apk & SystemUI.apk first,
        // AND discover APK, JAR, and VDEX/ODEX containers (including live-mapped /proc/<pid>/maps oat/vdex paths)!
        val arscIdMap = HashMap<Int, ArscEntryRecord>(4096)

        procLiveMaps.forEach { rec ->
            (rec.mappedApks + rec.mappedJarsAndDex).forEach { mapped ->
                val l = mapped.lowercase()
                if ((l.endsWith(".apk") || l.endsWith(".jar") || l.endsWith(".vdex") || l.endsWith(".odex")) &&
                    (l.contains("systemui") || l.contains("services") || l.contains("framework") ||
                        l.contains("biometric") || l.contains("fingerprint") || l.contains("udfps") ||
                        l.contains("fod") || l.contains("xiaomi") || l.contains("oplus") || l.contains("treble"))
                ) {
                    targetPaths += mapped
                }
            }
        }

        if (effectiveRoot) {
            ShellExecutor.exec(
                "ls -1 /system/framework/framework-res.apk /system/framework/services.jar /system/framework/framework.jar /system/framework/miui-services.jar /system/framework/oplus-services.jar /system/framework/oat/*/services.vdex /system_ext/priv-app/*SystemUI*/*.apk /system_ext/priv-app/*SystemUI*/oat/*/*.vdex /system/priv-app/*SystemUI*/*.apk /system/priv-app/*SystemUI*/oat/*/*.vdex /apex/*biometric*/javalib/*.jar /apex/*biometric*/bin/* 2>/dev/null",
                useRoot = true,
                timeoutMs = 5_000L
            ).stdout.lines().map { it.trim() }.filter { it.startsWith("/") }.forEach { targetPaths += it }
        }

        // First pass: load resources.arsc from framework-res.apk and SystemUI.apk so bytecode 0x7f/0x01 IDs resolve accurately
        val priorityOrderedPaths = targetPaths.sortedWith(
            compareByDescending<String> { it.contains("framework-res.apk", true) }
                .thenByDescending { it.contains("SystemUI.apk", true) }
                .thenByDescending { it.endsWith(".apk") || it.endsWith(".jar") }
        ).distinct().take(16)

        val cachedBytes = HashMap<String, ByteArray>()
        for (path in priorityOrderedPaths) {
            if (!path.endsWith(".apk") && !path.endsWith(".jar") && !path.endsWith(".vdex") && !path.endsWith(".odex")) continue
            val limitBytes = if (path.endsWith(".vdex") || path.endsWith(".jar") || path.contains("SystemUI", true)) 24 * 1024 * 1024 else 14 * 1024 * 1024
            val readRes = ShellExecutor.readBinaryFile(path, effectiveRoot, maxBytes = limitBytes)
            val bytes = readRes.bytes ?: continue
            cachedBytes[path] = bytes
            if (path.endsWith(".apk") && (path.contains("framework-res", true) || path.contains("SystemUI", true))) {
                extractArscBytesFromApk(bytes)?.let { arscRaw ->
                    arscIdMap.putAll(BinarySourceDecoder.buildArscIdLookupTable(arscRaw))
                }
            }
        }

        priorityOrderedPaths.forEachIndexed { idx, path ->
            val contents = mutableListOf<String>()
            val bytes = cachedBytes[path]

            if (path.endsWith(".apk") && bytes != null) {
                val parsed = parseApkBinaryFodDetails(bytes)
                contents += parsed.decodedArscEntries.take(16)
                contents += parsed.fodResourceStrings.take(12)
                if (path.contains("SystemUI", true)) {
                    contents += resolvePackageResourceValues(context.packageManager, "com.android.systemui", parsed.discoveredResourceKeys).take(16)
                }
            }

            if (bytes != null) {
                val targetHint = when {
                    path.contains("SystemUI", true) -> "SystemUI UDFPS/HBM Controller"
                    path.contains("services", true) -> "BiometricService / FingerprintService"
                    path.contains("framework", true) -> "Framework Resources / SensorProps"
                    path.contains("biometric", true) -> "Biometric APEX Module"
                    else -> "Runtime System Module"
                }
                val dexExtract = when {
                    path.endsWith(".vdex") || path.endsWith(".odex") ->
                        BinarySourceDecoder.extractFodDexSourcesFromVdexOrOat(bytes, path, targetHint, arscIdMap)
                    path.endsWith(".apk") || path.endsWith(".jar") ->
                        BinarySourceDecoder.extractFodDexSourcesFromArchive(bytes, path, targetHint, arscIdMap)
                    else -> null
                }
                if (dexExtract != null) {
                    dexExtracts += dexExtract
                    dexExtract.resolvedResourceKeys.take(10).forEach { contents += "R.id ref: $it" }
                    dexExtract.methodTraces.take(8).forEach { contents += "Bytecode trace: ${it.fqMethod} -> ${it.invokedMethods.take(3).joinToString(",")}" }
                    dexExtract.matchedClasses.take(8).forEach { contents += "DEX class: $it" }
                    dexExtract.matchedMethods.take(10).forEach { contents += "DEX method: $it" }
                    dexExtract.matchedStrings.take(8).forEach { contents += "DEX string: $it" }
                }
            }

            out += FileProvenanceArtifact(
                id = "prov_sysfw_$idx",
                category = "SYSTEMUI_FRAMEWORK",
                filePath = path,
                directory = path.substringBeforeLast('/'),
                matchedSymbolOrKey = path.substringAfterLast('/'),
                importantContents = contents.distinct().ifEmpty { listOf("Active runtime module at $path") }.take(34)
            )
        }
        return out to dexExtracts
    }

    private fun extractArscBytesFromApk(apkBytes: ByteArray): ByteArray? = runCatching {
        ZipInputStream(ByteArrayInputStream(apkBytes)).use { zip ->
            var entry = zip.nextEntry
            while (entry != null) {
                if (!entry.isDirectory && entry.name == "resources.arsc") {
                    return zip.readBytes()
                }
                zip.closeEntry()
                entry = zip.nextEntry
            }
        }
        null
    }.getOrNull()

    fun serializeOverlayDeepInspect(
        list: List<OverlayDeepInspection>,
        filteredNonFodCount: Int = 0
    ): String = buildString {
        appendLine("=== STRICT BYTECODE & LOOKUP PROVEN OVERLAY INSPECTIONS (${list.size} proven | $filteredNonFodCount generic UI filtered) ===")
        list.forEach { ov ->
            appendLine("OVERLAY: ${ov.packageName}")
            appendLine("  ENABLED=${ov.isEnabled} | STATIC=${ov.isStatic} | PRIORITY=${ov.priority} | TARGET=${ov.targetPackage} | SCORE=${ov.fodRelevanceScore} | LIVE_MAPPED=${ov.provenInLiveMaps} | STRICT_PROVEN=${ov.isStrictProvenFod}")
            appendLine("  APK_PATH=${ov.apkPath}")
            appendLine("  DIRECTORY=${ov.directory}")
            ov.bytecodeMatchedResourceKeys.forEach { appendLine("  BYTECODE_MATCH: $it") }
            ov.lookupWinners.forEach { appendLine("  LOOKUP_WINNER: $it") }
            ov.decodedArscEntries.forEach { appendLine("  ARSC_ENTRY: $it") }
            ov.manifestSummary.forEach { appendLine("  MANIFEST: $it") }
            ov.fodConfigEntries.forEach { appendLine("  CONTENT: $it") }
            if (ov.pseudoXmlSource.isNotBlank()) {
                appendLine("  PSEUDO_XML_START")
                ov.pseudoXmlSource.lineSequence().take(45).forEach { line ->
                    appendLine("  XML: $line")
                }
                appendLine("  PSEUDO_XML_END")
            }
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

    fun serializeDexSourceExtracts(list: List<DexSourceExtract>): String = buildString {
        appendLine("=== DEX & VDEX BYTECODE SOURCE EXTRACT (${list.size}) ===")
        list.forEach { dex ->
            appendLine("DEX_ARCHIVE: ${dex.archivePath} (${dex.targetHint}) [${dex.containerType}]")
            dex.resolvedResourceKeys.forEach { appendLine("  RES_KEY: $it") }
            dex.methodTraces.take(20).forEach { tr ->
                appendLine("  TRACE_METHOD: ${tr.fqMethod}")
                tr.resolvedResKeys.forEach { appendLine("    TRACE_RES: $it") }
                tr.invokedMethods.take(10).forEach { appendLine("    TRACE_CALL: $it") }
                tr.referencedStrings.take(6).forEach { appendLine("    TRACE_STR: $it") }
            }
            dex.matchedClasses.forEach { appendLine("  CLASS: $it") }
            dex.matchedMethods.forEach { appendLine("  METHOD: $it") }
            dex.matchedStrings.forEach { appendLine("  STRING: $it") }
            if (dex.sourcePseudoSummary.isNotBlank()) {
                appendLine("  SOURCE_OUTLINE_START")
                dex.sourcePseudoSummary.lineSequence().take(75).forEach { line ->
                    appendLine("  CODE: $line")
                }
                appendLine("  SOURCE_OUTLINE_END")
            }
            appendLine()
        }
    }

    fun serializeProcLiveMaps(list: List<LiveProcessMapRecord>): String = buildString {
        appendLine("=== LIVE ROOT /proc/<pid>/maps, fd & threads (${list.size} processes) ===")
        list.forEach { rec ->
            appendLine("PROCESS: ${rec.processName} (pid=${rec.pid})")
            rec.matchedFodPaths.forEach { appendLine("  FOD_MATCH: $it") }
            rec.activeThreads.take(25).forEach { appendLine("  THREAD: $it") }
            rec.mappedApks.forEach { appendLine("  MAPPED_APK: $it") }
            rec.mappedJarsAndDex.forEach { appendLine("  MAPPED_JAR: $it") }
            rec.mappedLibs.take(40).forEach { appendLine("  MAPPED_LIB: $it") }
            rec.openFds.take(40).forEach { appendLine("  OPEN_FD: $it") }
            rec.enrollmentNewMappedFiles.forEach { appendLine("  ENROLL_NEW_MAP: $it") }
            rec.enrollmentNewFds.forEach { appendLine("  ENROLL_NEW_FD: $it") }
            appendLine()
        }
    }
}
