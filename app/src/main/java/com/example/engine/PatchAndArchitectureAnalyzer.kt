package com.example.engine

import com.example.i18n.AppLanguage
import com.example.model.ComponentCategory
import com.example.model.DependencyEdge
import com.example.model.DetectedPatch
import com.example.model.DiagnosticMode
import com.example.model.DiagnosticSummary
import com.example.model.DiscoveredComponent
import com.example.model.ElfBinaryAnalysis
import com.example.model.EvidenceStatus
import com.example.model.FodDiagnosticReport
import com.example.model.InvestigationFinding
import com.example.model.KnowledgeLevel
import com.example.model.RawArtifactsBundle
import com.example.model.SessionEvent
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

object PatchAndArchitectureAnalyzer {

    private val patchPropRegex = Regex(
        "^(persist\\.sys\\.phh\\.|persist\\.sys\\.treble\\.|ro\\.vendor\\.fingerprint\\.|persist\\.vendor\\..*(fp|fod|udfps|hbm|bio)|ro\\.hardware\\.fp|vendor\\.fingerprint\\.|sys\\.fod\\.|persist\\.sys\\.fod|ro\\.oplus\\.fod|ro\\.miui\\.fod|ro\\.boot\\.fp).*",
        RegexOption.IGNORE_CASE
    )

    private val liveLogFilterRegex = Regex(
        "(fingerprint|biometric|udfps|fod|hbm|lhbm|dimlayer|zorder|surfaceflinger|enroll|goodix|fpc|silead|focal|egis|synaptics|avc:\\s*denied)",
        RegexOption.IGNORE_CASE
    )

    fun buildReport(
        mode: DiagnosticMode,
        baseline: BaselineProbeResult,
        liveLogcat: String,
        elfAnalyses: List<ElfBinaryAnalysis>,
        enrollmentDurationMs: Long,
        language: AppLanguage
    ): FodDiagnosticReport {
        val components = mutableListOf<DiscoveredComponent>()
        val edges = mutableListOf<DependencyEdge>()
        val patches = mutableListOf<DetectedPatch>()
        val findings = mutableListOf<InvestigationFinding>()

        val propMap = parseProperties(baseline.getpropAll)

        // 1. Discover HALs from lshal, VINTF, and service list
        discoverHalComponents(baseline, components)

        // 2. Discover System Framework / Biometric / SystemUI Udfps / Display Services
        discoverSystemServices(baseline, components)

        // 3. Discover Native Libraries & ELF Binaries
        discoverElfComponents(elfAnalyses, components)

        // 4. Discover Sysfs / DRM / HBM / LHBM hardware nodes
        discoverSysfsNodes(baseline, components)

        // 5. Discover Overlays & Patches (exhaustively, never skipping any)
        discoverPatchesAndOverlays(baseline, propMap, patches, components)

        // 6. Reconstruct real SESSION FLOW from live enrollment logcat
        val sessionFlow = reconstructSessionFlow(liveLogcat, baseline.environment.rootGranted, language)

        // 7. Build real Dependency Graph from discovered components
        buildDependencyGraph(components, sessionFlow, edges)

        // 8. Analyze benign warnings vs real blocking failures
        val blockingEvents = sessionFlow.filter { it.isBlockingFailure || it.status == EvidenceStatus.FAILED }
        val benignEvents = sessionFlow.filter { it.isBenignWarning }
        val enrollSuccess = sessionFlow.any {
            it.rawEvidence.contains("remaining=0", true) ||
                it.rawEvidence.contains("onEnrollResult", true) && it.rawEvidence.contains("0") ||
                it.rawEvidence.contains("enroll_complete", true)
        }
        val enrollFailed = blockingEvents.isNotEmpty() || sessionFlow.any {
            it.rawEvidence.contains("onError", true) ||
                it.rawEvidence.contains("ERROR_TIMEOUT", true) ||
                it.rawEvidence.contains("ERROR_HW_UNAVAILABLE", true) ||
                it.rawEvidence.contains("ERROR_UNABLE_TO_PROCESS", true)
        }

        // Evaluate patches real effect based on live session & dumpsys
        val evaluatedPatches = evaluatePatchesRealEffect(patches, sessionFlow, baseline, language)

        // Generate Epistemic Investigation Findings
        buildFindings(
            baseline = baseline,
            components = components,
            patches = evaluatedPatches,
            elfAnalyses = elfAnalyses,
            sessionFlow = sessionFlow,
            findings = findings,
            language = language
        )

        val confirmedCount = components.count { it.status == EvidenceStatus.CONFIRMED } +
            sessionFlow.count { it.status == EvidenceStatus.CONFIRMED }
        val observedCount = components.count { it.status == EvidenceStatus.OBSERVED } +
            sessionFlow.count { it.status == EvidenceStatus.OBSERVED }
        val suspectCount = components.count { it.status == EvidenceStatus.SUSPECT } +
            sessionFlow.count { it.status == EvidenceStatus.SUSPECT }
        val failedCount = components.count { it.status == EvidenceStatus.FAILED } +
            sessionFlow.count { it.status == EvidenceStatus.FAILED }
        val unknownCount = components.count { it.status == EvidenceStatus.UNKNOWN } +
            sessionFlow.count { it.status == EvidenceStatus.UNKNOWN }

        val firstBreak = blockingEvents.firstOrNull()?.let {
            "[${it.phase}] ${it.component}: ${it.summary} (${it.rawEvidence.take(160)})"
        } ?: if (components.any { it.status == EvidenceStatus.FAILED }) {
            val c = components.first { it.status == EvidenceStatus.FAILED }
            "[${c.category}] ${c.name}: ${c.accessNote ?: c.path}"
        } else {
            if (language == AppLanguage.FR) {
                "Aucune rupture bloquante démontrée dans les traces accessibles."
            } else {
                "No blocking break demonstrated within accessible traces."
            }
        }

        val noiseNote = when {
            enrollSuccess && benignEvents.isNotEmpty() -> {
                if (language == AppLanguage.FR) {
                    "Enregistrement réussi malgré ${benignEvents.size} avertissement(s) non bloquant(s) observé(s) dans les logs."
                } else {
                    "Enrollment succeeded despite ${benignEvents.size} non-blocking warning(s) observed in logs."
                }
            }
            enrollFailed && benignEvents.isNotEmpty() -> {
                if (language == AppLanguage.FR) {
                    "${benignEvents.size} avertissement(s) bénin(s) et ${blockingEvents.size} rupture(s) bloquante(s) observés."
                } else {
                    "${benignEvents.size} benign warning(s) and ${blockingEvents.size} blocking break(s) observed."
                }
            }
            else -> {
                if (language == AppLanguage.FR) {
                    "Distinction effectuée entre bruit système toléré et erreurs fatales."
                } else {
                    "Separated tolerated system log noise from fatal breaks."
                }
            }
        }

        val overallOutcome = when {
            sessionFlow.isEmpty() -> if (language == AppLanguage.FR) {
                "INCOMPLET / TRACE LIVE RESTREINTE"
            } else {
                "INCOMPLETE / RESTRICTED LIVE TRACE"
            }
            enrollSuccess && !enrollFailed -> if (language == AppLanguage.FR) {
                "SUCCÈS D'ENREGISTREMENT OBSERVÉ"
            } else {
                "ENROLLMENT SUCCESS OBSERVED"
            }
            enrollFailed -> if (language == AppLanguage.FR) {
                "BLOCAGE RÉEL DÉTECTÉ"
            } else {
                "REAL ENROLLMENT BLOCK DETECTED"
            }
            else -> if (language == AppLanguage.FR) {
                "SESSION OBSERVÉE (ÉTAT INTERMÉDIAIRE)"
            } else {
                "SESSION OBSERVED (INTERMEDIATE STATE)"
            }
        }

        val fullElfText = buildString {
            elfAnalyses.forEach { elf ->
                appendLine("====================================================")
                appendLine("BINARY: ${elf.path} (${elf.architecture}, ${elf.fileSizeBytes} bytes)")
                appendLine("Readable: ${elf.isReadable} | AccessError: ${elf.accessError ?: "none"}")
                appendLine("DT_NEEDED: ${elf.dtNeeded.joinToString(", ")}")
                appendLine("FOD Symbols (${elf.fodSymbols.size}):")
                elf.fodSymbols.forEach { appendLine("  - $it") }
                appendLine("FOD Strings (${elf.fodStrings.size}):")
                elf.fodStrings.forEach { appendLine("  - $it") }
                if (elf.disassemblyPseudoCode.isNotBlank()) {
                    appendLine("AArch64 Disassembly / Pseudo-code:")
                    appendLine(elf.disassemblyPseudoCode)
                }
                appendLine()
            }
        }

        val nowIso = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).format(Date())

        return FodDiagnosticReport(
            sessionId = UUID.randomUUID().toString().take(8),
            mode = mode,
            createdAtIso = nowIso,
            enrollmentDurationMs = enrollmentDurationMs,
            environment = baseline.environment,
            sessionFlow = sessionFlow,
            components = components.distinctBy { it.id },
            dependencyEdges = edges,
            patches = evaluatedPatches,
            elfAnalyses = elfAnalyses,
            findings = findings,
            summary = DiagnosticSummary(
                overallOutcome = overallOutcome,
                enrollmentObserved = sessionFlow.isNotEmpty(),
                enrollmentSucceeded = when {
                    enrollSuccess && !enrollFailed -> true
                    enrollFailed -> false
                    else -> null
                },
                realSuccessDespiteNoiseNote = noiseNote,
                firstDemonstratedBreak = firstBreak,
                confirmedCount = confirmedCount,
                observedCount = observedCount,
                suspectCount = suspectCount,
                failedCount = failedCount,
                unknownCount = unknownCount
            ),
            rawArtifacts = RawArtifactsBundle(
                logcatBaseline = baseline.logcatBaseline,
                logcatEnrollment = liveLogcat,
                dumpsysFingerprint = baseline.dumpsysFingerprint,
                dumpsysBiometric = baseline.dumpsysBiometric,
                dumpsysSurfaceFlinger = baseline.dumpsysSurfaceFlinger,
                dumpsysDisplay = baseline.dumpsysDisplay,
                dumpsysOverlay = baseline.dumpsysOverlay,
                lshalOutput = baseline.lshalOutput,
                vintfManifests = baseline.vintfManifests,
                serviceList = baseline.serviceList,
                getpropAll = baseline.getpropAll,
                sysfsFodNodes = baseline.sysfsFodNodes,
                selinuxDenials = baseline.selinuxDenials,
                initRcSnippets = baseline.initRcSnippets,
                elfDisassemblyFull = fullElfText
            )
        )
    }

    private fun discoverHalComponents(
        baseline: BaselineProbeResult,
        out: MutableList<DiscoveredComponent>
    ) {
        val combined = listOf(baseline.lshalOutput, baseline.vintfManifests, baseline.serviceList)
            .joinToString("\n")
        val halPatterns = Regex(
            "(android\\.hardware\\.biometrics\\.fingerprint[@\\d.]*[:/\\w.-]*|vendor\\.[\\w.]+fingerprint[\\w.@:/-]*|vendor\\.[\\w.]+biometrics[\\w.@:/-]*|vendor\\.[\\w.]+display[\\w.@:/-]*)",
            RegexOption.IGNORE_CASE
        )

        val matched = halPatterns.findAll(combined).map { it.value.trim() }.distinct().toList()
        if (matched.isEmpty()) {
            out += DiscoveredComponent(
                id = "hal_fingerprint_unknown",
                name = "Fingerprint HAL (HIDL/AIDL)",
                category = ComponentCategory.HAL,
                version = "UNKNOWN",
                interfaceType = "UNKNOWN",
                path = "/vendor/bin/hw/*",
                status = if (baseline.environment.rootGranted) EvidenceStatus.FAILED else EvidenceStatus.UNKNOWN,
                knowledgeLevel = KnowledgeLevel.FACT,
                accessNote = if (baseline.environment.rootGranted) {
                    "No fingerprint HAL instance detected in lshal/VINTF/service list."
                } else {
                    "lshal/VINTF restricted without root; HAL identity cannot be confirmed."
                }
            )
        } else {
            matched.forEachIndexed { idx, halName ->
                val isAidl = halName.contains("IFingerprint", true) || !halName.contains("@")
                val version = Regex("@(\\d+\\.\\d+)").find(halName)?.groupValues?.get(1)
                    ?: if (isAidl) "AIDL" else "UNKNOWN"
                val status = if (baseline.lshalOutput.contains(halName) || baseline.serviceList.contains(halName)) {
                    EvidenceStatus.CONFIRMED
                } else {
                    EvidenceStatus.OBSERVED
                }
                out += DiscoveredComponent(
                    id = "hal_${idx}_${halName.hashCode()}",
                    name = halName,
                    category = ComponentCategory.HAL,
                    version = version,
                    interfaceType = if (isAidl) "AIDL Binder" else "HIDL hwbinder",
                    path = "VINTF / Binder",
                    status = status,
                    knowledgeLevel = KnowledgeLevel.FACT,
                    metadata = mapOf("source" to if (baseline.lshalOutput.contains(halName)) "lshal" else "vintf/service_list")
                )
            }
        }
    }

    private fun discoverSystemServices(
        baseline: BaselineProbeResult,
        out: MutableList<DiscoveredComponent>
    ) {
        val fpPresent = baseline.dumpsysFingerprint.isNotBlank() &&
            !baseline.dumpsysFingerprint.contains("Can't find service", true)
        val udfpsInfo = Regex("(udfps|fod|sensorLocation|sensorProps|HBM|LHBM).*", RegexOption.IGNORE_CASE)
            .findAll(baseline.dumpsysFingerprint + "\n" + baseline.dumpsysBiometric)
            .map { it.value.trim().take(120) }
            .distinct()
            .take(8)
            .joinToString(" | ")

        out += DiscoveredComponent(
            id = "svc_fingerprint",
            name = "FingerprintService / BiometricService",
            category = ComponentCategory.SERVICE,
            version = "Android ${baseline.environment.androidRelease} (API ${baseline.environment.sdkInt})",
            interfaceType = "SystemServer Binder",
            path = "system_server",
            status = when {
                fpPresent && udfpsInfo.isNotBlank() -> EvidenceStatus.CONFIRMED
                fpPresent -> EvidenceStatus.OBSERVED
                baseline.environment.biometricHardwareStatus.contains("BIOMETRIC_ERROR_NO_HARDWARE") -> EvidenceStatus.FAILED
                else -> EvidenceStatus.UNKNOWN
            },
            knowledgeLevel = KnowledgeLevel.FACT,
            metadata = mapOf(
                "biometricManager" to baseline.environment.biometricHardwareStatus,
                "udfpsHints" to udfpsInfo.ifBlank { "none observed in accessible dumpsys" }
            ),
            accessNote = if (!fpPresent) "dumpsys fingerprint inaccessible or empty (Permission denied without shell/root)." else null
        )

        val sfPresent = baseline.dumpsysSurfaceFlinger.isNotBlank()
        val sfFodLayer = Regex("(Udfps|Fod|Fingerprint|HBM|Dim|ColorMode).*", RegexOption.IGNORE_CASE)
            .findAll(baseline.dumpsysSurfaceFlinger)
            .map { it.value.trim().take(120) }
            .distinct()
            .take(6)
            .joinToString(" | ")

        out += DiscoveredComponent(
            id = "svc_surfaceflinger",
            name = "SurfaceFlinger / HWC Display Pipeline",
            category = ComponentCategory.DISPLAY_PIPELINE,
            version = "Display API ${baseline.environment.sdkInt}",
            interfaceType = "Composer HAL / DRM",
            path = "/system/bin/surfaceflinger",
            status = if (sfPresent) EvidenceStatus.CONFIRMED else EvidenceStatus.UNKNOWN,
            knowledgeLevel = KnowledgeLevel.FACT,
            metadata = mapOf(
                "displayModes" to baseline.environment.displayModesSummary,
                "fodLayers" to sfFodLayer.ifBlank { "none observed at baseline" }
            ),
            accessNote = if (!sfPresent) "dumpsys SurfaceFlinger blocked without root/DUMP permission." else null
        )
    }

    private fun discoverElfComponents(
        elfAnalyses: List<ElfBinaryAnalysis>,
        out: MutableList<DiscoveredComponent>
    ) {
        if (elfAnalyses.isEmpty()) {
            out += DiscoveredComponent(
                id = "elf_none",
                name = "Vendor/System FOD ELF Binaries",
                category = ComponentCategory.LIBRARY,
                version = "UNKNOWN",
                interfaceType = "ELF",
                path = "/vendor/bin/hw/ & /vendor/lib64/",
                status = EvidenceStatus.UNKNOWN,
                knowledgeLevel = KnowledgeLevel.FACT,
                accessNote = "No accessible FOD/fingerprint ELF binaries discovered (SELinux/non-root restriction or non-standard path)."
            )
            return
        }

        elfAnalyses.forEachIndexed { idx, elf ->
            out += DiscoveredComponent(
                id = "elf_${idx}_${elf.path.hashCode()}",
                name = elf.path.substringAfterLast('/'),
                category = if (elf.path.contains("/bin/")) ComponentCategory.HAL else ComponentCategory.LIBRARY,
                version = elf.architecture,
                interfaceType = "ELF (${elf.fileSizeBytes} bytes)",
                path = elf.path,
                status = if (elf.isReadable) EvidenceStatus.CONFIRMED else EvidenceStatus.UNKNOWN,
                knowledgeLevel = KnowledgeLevel.FACT,
                dependencies = elf.dtNeeded,
                metadata = mapOf(
                    "symbolsCount" to elf.fodSymbols.size.toString(),
                    "stringsCount" to elf.fodStrings.size.toString()
                ),
                accessNote = elf.accessError
            )
        }
    }

    private fun discoverSysfsNodes(
        baseline: BaselineProbeResult,
        out: MutableList<DiscoveredComponent>
    ) {
        val sections = baseline.sysfsFodNodes.split("=== ")
            .map { it.trim() }
            .filter { it.isNotBlank() }

        if (sections.isEmpty()) {
            out += DiscoveredComponent(
                id = "sysfs_fod_unknown",
                name = "Sysfs HBM / LHBM / FOD Nodes",
                category = ComponentCategory.SYSFS_NODE,
                version = "Kernel Sysfs",
                interfaceType = "sysfs/ioctl",
                path = "/sys/class/drm/ & /sys/devices/",
                status = EvidenceStatus.UNKNOWN,
                knowledgeLevel = KnowledgeLevel.FACT,
                accessNote = "No readable FOD/HBM sysfs nodes found (SELinux/non-root restriction or vendor uses DRM ioctl/AIDL)."
            )
            return
        }

        sections.forEachIndexed { idx, block ->
            val lines = block.lines()
            val nodePath = lines.firstOrNull()?.removeSuffix("===")?.trim() ?: return@forEachIndexed
            val value = lines.drop(1).joinToString(" ").trim()
            val denied = value.contains("Permission denied", true)
            out += DiscoveredComponent(
                id = "sysfs_${idx}_${nodePath.hashCode()}",
                name = nodePath.substringAfterLast('/'),
                category = ComponentCategory.SYSFS_NODE,
                version = "Kernel",
                interfaceType = "sysfs",
                path = nodePath,
                status = if (denied) EvidenceStatus.UNKNOWN else EvidenceStatus.CONFIRMED,
                knowledgeLevel = KnowledgeLevel.FACT,
                metadata = mapOf("value" to value.take(180)),
                accessNote = if (denied) "Permission denied reading $nodePath" else null
            )
        }
    }

    private fun discoverPatchesAndOverlays(
        baseline: BaselineProbeResult,
        propMap: Map<String, String>,
        patches: MutableList<DetectedPatch>,
        components: MutableList<DiscoveredComponent>
    ) {
        // Every FOD/Treble/GSI/Vendor property detected
        propMap.entries
            .filter { patchPropRegex.matches(it.key) || it.key.contains("fod", true) || it.key.contains("udfps", true) || it.key.contains("phh", true) }
            .forEachIndexed { idx, (k, v) ->
                val isPhhOrGsi = k.contains("phh", true) || k.contains("treble", true) || k.contains("sys.fod", true)
                patches += DetectedPatch(
                    id = "patch_prop_$idx",
                    name = k,
                    source = "SystemProperties (getprop)",
                    scope = if (isPhhOrGsi) "GSI / Treble Patch Prop" else "Device / Vendor Prop",
                    target = k,
                    rawValue = v,
                    status = EvidenceStatus.CONFIRMED,
                    realObservedEffect = "Pending live trace correlation",
                    note = "Detected active property [$k]=[$v]"
                )
                components += DiscoveredComponent(
                    id = "prop_$idx",
                    name = k,
                    category = if (isPhhOrGsi) ComponentCategory.PATCH else ComponentCategory.PROPERTY,
                    version = v.ifBlank { "<empty>" },
                    interfaceType = "SystemProperty",
                    path = k,
                    status = EvidenceStatus.CONFIRMED,
                    knowledgeLevel = KnowledgeLevel.FACT
                )
            }

        // Every RRO overlay from cmd overlay list & installed packages
        baseline.dumpsysOverlay.lineSequence()
            .filter {
                val l = it.lowercase()
                l.contains("fod") || l.contains("udfps") || l.contains("treble") ||
                    l.contains("fingerprint") || l.contains("biometric") || l.contains("systemui")
            }
            .distinct()
            .take(50)
            .forEachIndexed { idx, line ->
                val trimmed = line.trim()
                val enabled = trimmed.startsWith("[x]", true) || trimmed.contains("STATE_ENABLED")
                val pkg = trimmed.removePrefix("[x]").removePrefix("[ ]").trim()
                patches += DetectedPatch(
                    id = "patch_rro_$idx",
                    name = pkg,
                    source = "OverlayManager (cmd overlay list)",
                    scope = "RRO Overlay",
                    target = pkg,
                    rawValue = if (enabled) "ENABLED" else "DISABLED/STATE_OTHER",
                    status = if (enabled) EvidenceStatus.CONFIRMED else EvidenceStatus.OBSERVED,
                    realObservedEffect = if (enabled) "Active RRO overlay" else "Present but inactive",
                    note = trimmed
                )
                components += DiscoveredComponent(
                    id = "overlay_$idx",
                    name = pkg,
                    category = ComponentCategory.OVERLAY,
                    version = if (enabled) "ENABLED" else "INACTIVE",
                    interfaceType = "RRO",
                    path = pkg,
                    status = if (enabled) EvidenceStatus.CONFIRMED else EvidenceStatus.OBSERVED,
                    knowledgeLevel = KnowledgeLevel.FACT
                )
            }

        baseline.installedOverlayPackages.forEachIndexed { idx, pkg ->
            if (patches.none { it.name.contains(pkg) }) {
                patches += DetectedPatch(
                    id = "patch_pkg_$idx",
                    name = pkg,
                    source = "PackageManager",
                    scope = "Installed Overlay/FOD Package",
                    target = pkg,
                    rawValue = "INSTALLED",
                    status = EvidenceStatus.OBSERVED,
                    realObservedEffect = "Installed package (activation state from OverlayManager if accessible)",
                    note = pkg
                )
            }
        }

        // Init.rc FOD/fingerprint triggers
        baseline.initRcSnippets.lineSequence()
            .filter { it.isNotBlank() }
            .take(40)
            .forEachIndexed { idx, line ->
                patches += DetectedPatch(
                    id = "patch_init_$idx",
                    name = line.substringBefore(":"),
                    source = "init.rc",
                    scope = "Init Boot/Trigger Script",
                    target = line.substringBefore(":"),
                    rawValue = line.substringAfter(":").trim(),
                    status = EvidenceStatus.OBSERVED,
                    realObservedEffect = "Init trigger definition",
                    note = line.take(180)
                )
            }
    }

    private fun reconstructSessionFlow(
        liveLogcat: String,
        rootGranted: Boolean,
        language: AppLanguage
    ): List<SessionEvent> {
        if (liveLogcat.isBlank() || liveLogcat.startsWith("LOGCAT_UNAVAILABLE")) {
            return listOf(
                SessionEvent(
                    id = "flow_unavail",
                    timestamp = "N/A",
                    relativeMs = 0L,
                    phase = "CAPTURE",
                    component = "logcat",
                    summary = if (language == AppLanguage.FR) {
                        "Journaux système non accessibles (${liveLogcat.take(100)}). Aucun événement inventé."
                    } else {
                        "System logs inaccessible (${liveLogcat.take(100)}). No events fabricated."
                    },
                    rawEvidence = liveLogcat,
                    status = EvidenceStatus.UNKNOWN,
                    knowledgeLevel = KnowledgeLevel.FACT
                )
            )
        }

        val events = mutableListOf<SessionEvent>()
        val filteredLines = liveLogcat.lineSequence()
            .filter { liveLogFilterRegex.containsMatchIn(it) }
            .toList()

        filteredLines.takeLast(220).forEachIndexed { idx, line ->
            val lower = line.lowercase()
            val timestamp = line.take(18).trim()
            val phase = when {
                lower.contains("enroll") || lower.contains("biometricprompt") -> "ENROLLMENT"
                lower.contains("udfps") || lower.contains("fod") -> "FOD_OVERLAY"
                lower.contains("hbm") || lower.contains("lhbm") || lower.contains("surfaceflinger") || lower.contains("dim") -> "DISPLAY_HBM"
                lower.contains("avc:") -> "SELINUX"
                lower.contains("hal") || lower.contains("goodix") || lower.contains("fpc") || lower.contains("silead") -> "HAL_EXEC"
                else -> "BIOMETRIC_SVC"
            }

            val isBenignNoise = (lower.contains(" w ") || lower.contains("warning") ||
                lower.contains("deprecated") || lower.contains("not found") && !lower.contains("hal")) &&
                !lower.contains("fatal") && !lower.contains("deadobject") && !lower.contains("avc: denied")

            val isBlocking = lower.contains("avc: denied") && (lower.contains("fingerprint") || lower.contains("fod") || lower.contains("hbm") || lower.contains("sysfs")) ||
                lower.contains("deadobjectexception") ||
                lower.contains("error_hw_unavailable") ||
                lower.contains("error_unable_to_process") ||
                lower.contains("failed to open") ||
                lower.contains("permission denied") && (lower.contains("fod") || lower.contains("hbm") || lower.contains("fingerprint")) ||
                lower.contains("hal died") ||
                lower.contains("null sensor")

            val isConfirmed = lower.contains("onacquired") ||
                lower.contains("onenrollresult") ||
                lower.contains("onfingerdown") ||
                lower.contains("onfingerup") ||
                lower.contains("hbm enable") ||
                lower.contains("lhbm") && !lower.contains("fail") && !lower.contains("error")

            val status = when {
                isBlocking -> EvidenceStatus.FAILED
                isConfirmed -> EvidenceStatus.CONFIRMED
                isBenignNoise -> EvidenceStatus.SUSPECT
                else -> EvidenceStatus.OBSERVED
            }

            events += SessionEvent(
                id = "evt_$idx",
                timestamp = timestamp,
                relativeMs = idx * 10L,
                phase = phase,
                component = extractTagFromLogLine(line),
                summary = line.substringAfter(":", line).trim().take(160),
                rawEvidence = line,
                status = status,
                knowledgeLevel = KnowledgeLevel.FACT,
                isBenignWarning = isBenignNoise,
                isBlockingFailure = isBlocking
            )
        }

        if (events.isEmpty()) {
            events += SessionEvent(
                id = "flow_empty_scope",
                timestamp = "N/A",
                relativeMs = 0L,
                phase = "CAPTURE",
                component = if (rootGranted) "logcat" else "app_sandbox",
                summary = if (language == AppLanguage.FR) {
                    "Aucun événement FOD visible dans les tampons accessibles (sans root/READ_LOGS, Android isole les logs d'autres UID)."
                } else {
                    "No FOD events visible in accessible log buffers (without root/READ_LOGS, Android isolates cross-UID logs)."
                },
                rawEvidence = "Filtered 0 FOD lines from ${liveLogcat.lines().size} accessible lines",
                status = EvidenceStatus.UNKNOWN,
                knowledgeLevel = KnowledgeLevel.FACT
            )
        }

        return events
    }

    private fun extractTagFromLogLine(line: String): String {
        val parts = line.trim().split(Regex("\\s+"))
        return parts.drop(4).firstOrNull()?.substringBefore(":")?.take(40) ?: "system"
    }

    private fun evaluatePatchesRealEffect(
        patches: List<DetectedPatch>,
        sessionFlow: List<SessionEvent>,
        baseline: BaselineProbeResult,
        language: AppLanguage
    ): List<DetectedPatch> {
        val hasHbmEvent = sessionFlow.any { it.phase == "DISPLAY_HBM" && it.status == EvidenceStatus.CONFIRMED }
        val hasFodOverlay = sessionFlow.any { it.phase == "FOD_OVERLAY" && it.status == EvidenceStatus.CONFIRMED }
        val hasBlocking = sessionFlow.any { it.isBlockingFailure }

        return patches.map { p ->
            val effect = when {
                p.name.contains("hbm", true) && hasHbmEvent ->
                    if (language == AppLanguage.FR) "Corrélé avec une activation HBM observée." else "Correlated with observed HBM activation."
                p.name.contains("phh", true) && hasBlocking ->
                    if (language == AppLanguage.FR) "Présent mais n'empêche pas la rupture bloquante observée." else "Present, yet did not prevent the observed blocking break."
                p.scope == "RRO Overlay" && p.rawValue == "ENABLED" && hasFodOverlay ->
                    if (language == AppLanguage.FR) "Overlay actif pendant la session FOD." else "Overlay active during FOD session."
                else -> p.realObservedEffect
            }
            p.copy(realObservedEffect = effect)
        }
    }

    private fun buildDependencyGraph(
        components: List<DiscoveredComponent>,
        sessionFlow: List<SessionEvent>,
        out: MutableList<DependencyEdge>
    ) {
        val bioSvc = components.firstOrNull { it.id == "svc_fingerprint" }
        val sfSvc = components.firstOrNull { it.id == "svc_surfaceflinger" }
        val hals = components.filter { it.category == ComponentCategory.HAL }
        val libs = components.filter { it.category == ComponentCategory.LIBRARY }
        val sysfs = components.filter { it.category == ComponentCategory.SYSFS_NODE }
        val overlays = components.filter { it.category == ComponentCategory.OVERLAY || it.category == ComponentCategory.PATCH }

        if (bioSvc != null) {
            hals.forEach { hal ->
                val halFailed = sessionFlow.any { it.isBlockingFailure && it.phase == "HAL_EXEC" }
                out += DependencyEdge(
                    fromId = bioSvc.id,
                    toId = hal.id,
                    relation = hal.interfaceType,
                    status = if (halFailed) EvidenceStatus.FAILED else hal.status,
                    note = "BiometricService <-> ${hal.name}"
                )
            }
            if (sfSvc != null) {
                val hbmFailed = sessionFlow.any { it.isBlockingFailure && it.phase == "DISPLAY_HBM" }
                out += DependencyEdge(
                    fromId = bioSvc.id,
                    toId = sfSvc.id,
                    relation = "Udfps / HBM Trigger",
                    status = if (hbmFailed) EvidenceStatus.FAILED else sfSvc.status,
                    note = "FOD illumination & touch sync"
                )
            }
        }

        hals.firstOrNull()?.let { primaryHal ->
            libs.take(6).forEach { lib ->
                out += DependencyEdge(
                    fromId = primaryHal.id,
                    toId = lib.id,
                    relation = "ELF DT_NEEDED",
                    status = lib.status,
                    note = lib.path
                )
            }
            sysfs.take(6).forEach { node ->
                out += DependencyEdge(
                    fromId = primaryHal.id,
                    toId = node.id,
                    relation = "sysfs / ioctl",
                    status = node.status,
                    note = node.path
                )
            }
        }

        if (sfSvc != null) {
            sysfs.take(4).forEach { node ->
                out += DependencyEdge(
                    fromId = sfSvc.id,
                    toId = node.id,
                    relation = "DRM / HBM Node",
                    status = node.status,
                    note = node.path
                )
            }
        }

        if (bioSvc != null) {
            overlays.take(5).forEach { ov ->
                out += DependencyEdge(
                    fromId = ov.id,
                    toId = bioSvc.id,
                    relation = "Config / Patch",
                    status = ov.status,
                    note = ov.name
                )
            }
        }
    }

    private fun buildFindings(
        baseline: BaselineProbeResult,
        components: List<DiscoveredComponent>,
        patches: List<DetectedPatch>,
        elfAnalyses: List<ElfBinaryAnalysis>,
        sessionFlow: List<SessionEvent>,
        findings: MutableList<InvestigationFinding>,
        language: AppLanguage
    ) {
        findings += InvestigationFinding(
            id = "find_env",
            title = if (language == AppLanguage.FR) "Empreinte matérielle & partitionnement" else "Hardware & Partition Baseline",
            detail = "Device=${baseline.environment.deviceModel}, GSI=${baseline.environment.isGsiSuspected}, SELinux=${baseline.environment.selinuxMode}, Root=${baseline.environment.rootGranted}",
            evidenceSnippet = "boot=${baseline.environment.bootSignature} | vendor=${baseline.environment.vendorFingerprint}",
            status = EvidenceStatus.CONFIRMED,
            knowledgeLevel = KnowledgeLevel.FACT
        )

        val readableElfs = elfAnalyses.count { it.isReadable }
        findings += InvestigationFinding(
            id = "find_elf",
            title = if (language == AppLanguage.FR) "Couverture binaire ELF" else "ELF Binary Coverage",
            detail = "$readableElfs/${elfAnalyses.size} binaries readable for symbol & AArch64 disassembly.",
            evidenceSnippet = elfAnalyses.take(3).joinToString(" | ") { "${it.path}: ${it.fodSymbols.size} symbols" },
            status = if (readableElfs > 0) EvidenceStatus.CONFIRMED else EvidenceStatus.UNKNOWN,
            knowledgeLevel = KnowledgeLevel.FACT
        )

        findings += InvestigationFinding(
            id = "find_patches",
            title = if (language == AppLanguage.FR) "Inventaire complet des patchs/props/overlays" else "Complete Patch/Prop/Overlay Inventory",
            detail = "${patches.size} patchs, propriétés et overlays FOD/Treble recensés.",
            evidenceSnippet = patches.take(5).joinToString(" ; ") { "${it.name}=${it.rawValue}" },
            status = if (patches.isNotEmpty()) EvidenceStatus.CONFIRMED else EvidenceStatus.OBSERVED,
            knowledgeLevel = KnowledgeLevel.FACT
        )

        sessionFlow.filter { it.isBlockingFailure }.take(6).forEachIndexed { idx, evt ->
            findings += InvestigationFinding(
                id = "find_block_$idx",
                title = "${evt.phase}: ${evt.component}",
                detail = evt.summary,
                evidenceSnippet = evt.rawEvidence,
                status = EvidenceStatus.FAILED,
                knowledgeLevel = KnowledgeLevel.FACT,
                isBlocking = true
            )
        }

        sessionFlow.filter { it.isBenignWarning }.take(5).forEachIndexed { idx, evt ->
            findings += InvestigationFinding(
                id = "find_noise_$idx",
                title = "${evt.phase}: ${evt.component}",
                detail = evt.summary,
                evidenceSnippet = evt.rawEvidence,
                status = EvidenceStatus.SUSPECT,
                knowledgeLevel = KnowledgeLevel.CORRELATION,
                isBenignNoise = true
            )
        }

        if (baseline.environment.accessLimitations.isNotEmpty()) {
            findings += InvestigationFinding(
                id = "find_limits",
                title = if (language == AppLanguage.FR) "Restrictions d'accès signalées" else "Reported Access Restrictions",
                detail = "${baseline.environment.accessLimitations.size} sonde(s) limitée(s) par les permissions ou SELinux.",
                evidenceSnippet = baseline.environment.accessLimitations.joinToString("\n"),
                status = EvidenceStatus.UNKNOWN,
                knowledgeLevel = KnowledgeLevel.FACT
            )
        }
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
}
