package com.example.engine

import com.example.i18n.AppLanguage
import com.example.model.BinderTraceRecord
import com.example.model.CausalChainLink
import com.example.model.DexMethodTrace
import com.example.model.DexSourceExtract
import com.example.model.EvidenceStatus
import com.example.model.ExtractableFileItem
import com.example.model.FileProvenanceArtifact
import com.example.model.KnowledgeLevel
import com.example.model.OverlayDeepInspection
import com.example.model.PortAnalysisResult
import com.example.model.PortFileDiffItem
import com.example.model.PortingCandidateSolution
import com.example.model.PortingTier
import com.example.model.RawZipArchiveBundle
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object PortAnalysisEngine {

    private val relevantPropRegex = Regex(
        "(fp|fod|udfps|fingerprint|biometric|hbm|lhbm|display|drm|surfaceflinger|treble|phh|sf\\.|hwc|vendor\\.|oplus|miui|xiaomi|goodix|fpc|silead|focal|egis|keymaster|gatekeeper|tee)",
        RegexOption.IGNORE_CASE
    )

    private val propLineRegex = Regex("^\\[(.+?)\\]: \\[(.*)\\]$")
    private val avcPermRegex = Regex("\\{[^}]+\\}")
    private val avcTclassRegex = Regex("tclass=\\S+")
    private val avcScontextRegex = Regex("scontext=u:r:([^:]+):")
    private val fodArscSignalRegex = Regex(
        "(fod|udfps|fingerprint|biometric|hbm|lhbm|dimlayer|doze|burn_in|illumination|optical|ultrasonic|goodix|fpc|silead|focal|egis|synaptics|disp_param|touch_dev|xiaomi|oplus|phh|treble|sensor)",
        RegexOption.IGNORE_CASE
    )

    fun analyze(
        romZip: RawZipArchiveBundle,
        gsiZip: RawZipArchiveBundle,
        language: AppLanguage
    ): PortAnalysisResult {
        val romRep = romZip.report
        val gsiRep = gsiZip.report

        val romBoot = romRep?.environment?.bootSignature ?: extractEnvField(romZip, "Boot Signature")
        val gsiBoot = gsiRep?.environment?.bootSignature ?: extractEnvField(gsiZip, "Boot Signature")
        val romVendor = romRep?.environment?.vendorFingerprint ?: extractEnvField(romZip, "Vendor Fingerprint")
        val gsiVendor = gsiRep?.environment?.vendorFingerprint ?: extractEnvField(gsiZip, "Vendor Fingerprint")

        val bootMatch = FodComparatorEngine.areBootSignaturesCompatible(romBoot, gsiBoot)
        val vendorMatch = romVendor == gsiVendor || romVendor == "UNKNOWN" || gsiVendor == "UNKNOWN"
        val parityOk = bootMatch && vendorMatch
        val paritySummary = "ROM(boot=$romBoot, vendor=$romVendor) vs GSI(boot=$gsiBoot, vendor=$gsiVendor)"

        val factualDiffs = mutableListOf<PortFileDiffItem>()
        val sharedNoise = mutableListOf<PortFileDiffItem>()

        val romOverlays = loadOverlayInspections(romZip)
        val gsiOverlays = loadOverlayInspections(gsiZip)
        val romProvenance = loadFileProvenance(romZip)
        val gsiProvenance = loadFileProvenance(gsiZip)

        // 1. Exhaustive getprop_all.txt diff across ALL FOD/Display/Biometric/Treble/Vendor/System props
        diffGetpropFiles(romZip, gsiZip, factualDiffs, sharedNoise, language)

        // 2. Exhaustive cmd overlay / dumpsys_overlay + deep APK provenance diff
        diffOverlayFiles(romZip, gsiZip, romOverlays, gsiOverlays, factualDiffs, sharedNoise, language)

        // 3. dumpsys_fingerprint + dumpsys_biometric + dumpsys_display + dumpsys_surfaceflinger (noise-filtered!)
        diffDumpsysBiometricAndDisplay(romZip, gsiZip, factualDiffs, language)

        // 4. lshal + vintf_manifests + service_list
        diffHalAndBinderLayer(romZip, gsiZip, factualDiffs, sharedNoise, language)

        // 5. init_rc_snippets + sysfs_fod_nodes + selinux_denials + dynamic file provenance (XML, SELinux, prop files, SystemUI)
        diffInitSysfsAndSelinux(romZip, gsiZip, factualDiffs, sharedNoise, language)
        diffProvenanceArtifacts(romProvenance, gsiProvenance, factualDiffs, language)

        // 6. Live enrollment behavior (fingerDownChain, sysfsTransitions, dmesgDelta, logcat_enrollment)
        diffLiveExecutionAndLogs(romZip, gsiZip, factualDiffs, sharedNoise, language)

        // 7. ELF binaries & disassembly diff
        diffElfDisassembly(romZip, gsiZip, factualDiffs, language)

        // 8. Live root /proc/<pid>/maps + /proc/<pid>/fd and DEX source-level hooks diff
        diffLiveProcMapsAndDexSources(romZip, gsiZip, factualDiffs, language)

        val sortedDiffs = factualDiffs
            .distinctBy { "${it.sourceFile}::${it.title}" }
            .sortedWith(compareBy<PortFileDiffItem> { if (it.status == EvidenceStatus.FAILED) 0 else if (it.status == EvidenceStatus.SUSPECT) 1 else 2 }.thenBy { it.category })

        val sortedNoise = sharedNoise.distinctBy { "${it.sourceFile}::${it.title}" }

        // 8. Build actionable "Files & Mechanisms to Extract from Custom ROM" dossier
        val extractableFiles = buildExtractableFiles(
            romZip = romZip,
            gsiZip = gsiZip,
            romOverlays = romOverlays,
            gsiOverlays = gsiOverlays,
            romProvenance = romProvenance,
            gsiProvenance = gsiProvenance,
            diffs = sortedDiffs,
            language = language
        )

        // 9. Build ranked system/GSI porting solutions strictly respecting untouched boot & vendor
        val solutions = buildRankedPortingSolutions(
            romZip = romZip,
            gsiZip = gsiZip,
            diffs = sortedDiffs,
            extractables = extractableFiles,
            language = language
        )

        val verdict = buildFactualVerdict(
            romZip = romZip,
            gsiZip = gsiZip,
            diffs = sortedDiffs,
            solutions = solutions,
            extractables = extractableFiles,
            language = language
        )

        val romChain = resolveZipCausalChain(romZip, romOverlays.values.toList(), language)
        val gsiChain = resolveZipCausalChain(gsiZip, gsiOverlays.values.toList(), language)
        val causalBreakSummary = computeCausalBreakSummary(romChain, gsiChain, language)
        val rejectedNonFodCount = maxOf(
            romZip.report?.filteredNonFodOverlayCount ?: 0,
            parseFilteredNonFodCount(readRaw(romZip, "raw/overlay_deep_inspect.txt"))
        ) + sortedNoise.count { it.category == "GENERIC_UI_RRO_NOISE" }

        val nowIso = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).format(Date())
        return PortAnalysisResult(
            createdAtIso = nowIso,
            romSourceName = romZip.sourceName,
            gsiSourceName = gsiZip.sourceName,
            romFilesRead = romZip.totalFiles,
            gsiFilesRead = gsiZip.totalFiles,
            romTotalBytes = romZip.totalBytes,
            gsiTotalBytes = gsiZip.totalBytes,
            bootVendorParityVerified = parityOk,
            bootVendorParitySummary = paritySummary,
            factualRootCauseVerdict = verdict,
            factualDiffs = sortedDiffs,
            filteredSharedNoiseCount = sortedNoise.size,
            sharedNoiseSamples = sortedNoise,
            portingSolutions = solutions,
            extractableFiles = extractableFiles,
            romCausalChain = romChain,
            gsiCausalChain = gsiChain,
            causalBreakSummary = causalBreakSummary,
            filteredNonFodOverlayCount = rejectedNonFodCount
        )
    }

    private fun diffGetpropFiles(
        romZip: RawZipArchiveBundle,
        gsiZip: RawZipArchiveBundle,
        diffs: MutableList<PortFileDiffItem>,
        noise: MutableList<PortFileDiffItem>,
        language: AppLanguage
    ) {
        val romProps = parseProps(readRaw(romZip, "raw/getprop_all.txt"))
        val gsiProps = parseProps(readRaw(gsiZip, "raw/getprop_all.txt"))
        val allKeys = (romProps.keys + gsiProps.keys).distinct().sorted()

        for (key in allKeys) {
            if (!relevantPropRegex.containsMatchIn(key)) continue
            val rv = romProps[key]
            val gv = gsiProps[key]
            when {
                rv == gv -> Unit
                rv != null && gv == null -> {
                    val isBlocking = key.contains("fod", true) || key.contains("udfps", true) ||
                        key.contains("fingerprint", true) || key.contains("hbm", true) ||
                        key.contains("disp", true) || key.contains("surface", true)
                    diffs += PortFileDiffItem(
                        id = "prop_miss_${key.hashCode()}",
                        sourceFile = "raw/getprop_all.txt",
                        category = "PROPERTIES (getprop)",
                        title = key,
                        romEvidence = "[$key] = [$rv]",
                        gsiEvidence = if (language == AppLanguage.FR) "ABSENT de raw/getprop_all.txt" else "ABSENT in raw/getprop_all.txt",
                        impact = if (language == AppLanguage.FR) {
                            "Propriété active sur la Custom ROM absente sur la GSI."
                        } else {
                            "Property present on Custom ROM but missing on GSI."
                        },
                        status = if (isBlocking) EvidenceStatus.FAILED else EvidenceStatus.SUSPECT,
                        knowledgeLevel = KnowledgeLevel.FACT
                    )
                }
                rv == null && gv != null -> {
                    diffs += PortFileDiffItem(
                        id = "prop_gsi_${key.hashCode()}",
                        sourceFile = "raw/getprop_all.txt",
                        category = "PROPERTIES (getprop)",
                        title = key,
                        romEvidence = if (language == AppLanguage.FR) "Absent sur Custom ROM" else "Absent on Custom ROM",
                        gsiEvidence = "[$key] = [$gv]",
                        impact = if (language == AppLanguage.FR) {
                            "Propriété ajoutée côté GSI (vérifier si elle cible correctement le HAL vendor)."
                        } else {
                            "GSI-only property (verify compatibility with untouched vendor HAL)."
                        },
                        status = EvidenceStatus.OBSERVED,
                        knowledgeLevel = KnowledgeLevel.FACT
                    )
                }
                rv != null && gv != null -> {
                    // Ignore build/date/serial/vm telemetry noise
                    val isMetadataNoise = key.contains("build.date", true) ||
                        key.contains("build.id", true) ||
                        key.contains("build.display.id", true) ||
                        key.contains("build.version.", true) ||
                        key.contains("dalvik.vm.", true) ||
                        key.contains("persist.sys.timezone", true) ||
                        (key.contains("build.fingerprint", true) && !key.contains("vendor", true))
                    if (isMetadataNoise) {
                        noise += PortFileDiffItem(
                            id = "prop_build_${key.hashCode()}",
                            sourceFile = "raw/getprop_all.txt",
                            category = "METADATA_NOISE",
                            title = key,
                            romEvidence = rv,
                            gsiEvidence = gv,
                            impact = "Build/runtime metadata difference (non-blocking)",
                            status = EvidenceStatus.OBSERVED,
                            knowledgeLevel = KnowledgeLevel.FACT
                        )
                    } else {
                        diffs += PortFileDiffItem(
                            id = "prop_diff_${key.hashCode()}",
                            sourceFile = "raw/getprop_all.txt",
                            category = "PROPERTIES (getprop)",
                            title = key,
                            romEvidence = rv,
                            gsiEvidence = gv,
                            impact = if (language == AppLanguage.FR) "Valeur différente entre ROM et GSI." else "Divergent property value between ROM and GSI.",
                            status = EvidenceStatus.SUSPECT,
                            knowledgeLevel = KnowledgeLevel.FACT
                        )
                    }
                }
            }
        }
    }

    private fun diffOverlayFiles(
        romZip: RawZipArchiveBundle,
        gsiZip: RawZipArchiveBundle,
        romOverlays: Map<String, OverlayDeepInspection>,
        gsiOverlays: Map<String, OverlayDeepInspection>,
        diffs: MutableList<PortFileDiffItem>,
        noise: MutableList<PortFileDiffItem>,
        language: AppLanguage
    ) {
        val romLines = parseOverlayStates(readRaw(romZip, "raw/dumpsys_overlay.txt"))
        val gsiLines = parseOverlayStates(readRaw(gsiZip, "raw/dumpsys_overlay.txt"))
        val allNames = (romLines.keys + gsiLines.keys + romOverlays.keys + gsiOverlays.keys).distinct()

        val romDeepScannedFod = romOverlays.values.any {
            it.isStrictProvenFod ||
                it.bytecodeMatchedResourceKeys.isNotEmpty() ||
                it.fodRelevanceScore >= 30 ||
                it.fodConfigEntries.isNotEmpty() ||
                it.lookupWinners.isNotEmpty() ||
                it.decodedArscEntries.any { e -> fodArscSignalRegex.containsMatchIn(e) }
        }

        for (pkg in allNames) {
            val rDeep = romOverlays[pkg]
            val gDeep = gsiOverlays[pkg]
            val rEnabled = romLines[pkg] ?: rDeep?.isEnabled
            val gEnabled = gsiLines[pkg] ?: gDeep?.isEnabled
            val hasDeepFodSignal = rDeep != null && (
                rDeep.isStrictProvenFod ||
                    rDeep.bytecodeMatchedResourceKeys.isNotEmpty() ||
                    rDeep.fodRelevanceScore >= 30 ||
                    rDeep.fodConfigEntries.isNotEmpty() ||
                    rDeep.lookupWinners.isNotEmpty() ||
                    rDeep.decodedArscEntries.any { fodArscSignalRegex.containsMatchIn(it) }
                )
            val isBiometricOrDisplayOverlay = hasDeepFodSignal ||
                rDeep != null ||
                pkg.contains("fod", true) || pkg.contains("udfps", true) ||
                pkg.contains("fingerprint", true) || pkg.contains("biometric", true) ||
                pkg.contains("treble", true) || pkg.contains("systemui", true) ||
                pkg.contains("display", true) || pkg.contains("overlay", true)
            if (!isBiometricOrDisplayOverlay) continue

            val romLocNote = rDeep?.let { ov ->
                buildString {
                    append("Strict=${ov.isStrictProvenFod} | Score=${ov.fodRelevanceScore} | liveMapped=${ov.provenInLiveMaps} | APK=${ov.apkPath} (Dir=${ov.directory})")
                    if (ov.targetPackage.isNotBlank()) append(" -> target=${ov.targetPackage}")
                    if (ov.bytecodeMatchedResourceKeys.isNotEmpty()) append(" | BytecodeKeys: ${ov.bytecodeMatchedResourceKeys.take(3).joinToString("; ")}")
                    if (ov.lookupWinners.isNotEmpty()) append(" | Lookup: ${ov.lookupWinners.take(3).joinToString("; ")}")
                    val keys = (ov.decodedArscEntries + ov.fodConfigEntries).distinct()
                    if (keys.isNotEmpty()) append(" | Keys: ${keys.take(6).joinToString("; ")}")
                }
            }.orEmpty()

            when {
                rEnabled == true && (gEnabled == null || gEnabled == false) -> {
                    val isKnownExplicitGenericUi = pkg.contains("ambientcue", true) || pkg.contains("navbar", true)
                    val inspectedWithoutFodContent = rDeep != null &&
                        !rDeep.isStrictProvenFod &&
                        !hasDeepFodSignal &&
                        rDeep.apkPath != "UNKNOWN" &&
                        romDeepScannedFod &&
                        !pkg.contains("fod", true) &&
                        !pkg.contains("udfps", true) &&
                        !pkg.contains("fingerprint", true)
                    val isGenericNoise = isKnownExplicitGenericUi || inspectedWithoutFodContent
                    val targetList = if (isGenericNoise) noise else diffs
                    targetList += PortFileDiffItem(
                        id = "rro_miss_${pkg.hashCode()}",
                        sourceFile = if (rDeep != null && rDeep.apkPath != "UNKNOWN") rDeep.apkPath else "raw/dumpsys_overlay.txt",
                        category = if (inspectedWithoutFodContent) "GENERIC_UI_RRO_NOISE" else "RRO OVERLAYS",
                        title = pkg,
                        romEvidence = "[x] ENABLED" + if (romLocNote.isNotBlank()) "\n$romLocNote" else "",
                        gsiEvidence = if (gEnabled == null) "ABSENT" else "[ ] INACTIVE (${gDeep?.apkPath ?: "unknown path"})",
                        impact = if (inspectedWithoutFodContent) {
                            if (language == AppLanguage.FR) {
                                "Overlay UI générique inspecté (${rDeep.apkPath}) sans preuve bytecode/ARSC FOD → écarté comme faux positif."
                            } else {
                                "Generic UI overlay inspected (${rDeep.apkPath}) with zero bytecode/ARSC FOD proof → rejected as false positive."
                            }
                        } else if (language == AppLanguage.FR) {
                            "Overlay RRO actif sur Custom ROM mais absent/inactif sur GSI" +
                                (rDeep?.apkPath?.takeIf { it != "UNKNOWN" }?.let { " — fichier ROM à inspecter/extraire : $it" } ?: ".")
                        } else {
                            "RRO overlay enabled on Custom ROM yet missing/inactive on GSI" +
                                (rDeep?.apkPath?.takeIf { it != "UNKNOWN" }?.let { " — ROM APK file: $it" } ?: ".")
                        },
                        status = if (hasDeepFodSignal || pkg.contains("fod", true) || pkg.contains("udfps", true) || pkg.contains("fingerprint", true) || (!isGenericNoise && pkg.contains("systemui", true))) EvidenceStatus.FAILED else EvidenceStatus.SUSPECT,
                        knowledgeLevel = KnowledgeLevel.FACT
                    )
                }
                rEnabled == false && gEnabled == null -> {
                    noise += PortFileDiffItem(
                        id = "rro_inactive_${pkg.hashCode()}",
                        sourceFile = "raw/dumpsys_overlay.txt",
                        category = "INACTIVE_RRO_NOISE",
                        title = pkg,
                        romEvidence = "[ ] INACTIVE on ROM",
                        gsiEvidence = "ABSENT on GSI",
                        impact = if (language == AppLanguage.FR) {
                            "Overlay déjà INACTIF sur la ROM fonctionnelle → non bloquant."
                        } else {
                            "Overlay already INACTIVE on working ROM → non-blocking."
                        },
                        status = EvidenceStatus.OBSERVED,
                        knowledgeLevel = KnowledgeLevel.DEDUCTION
                    )
                }
                rEnabled == null && gEnabled == true -> {
                    diffs += PortFileDiffItem(
                        id = "rro_gsionly_${pkg.hashCode()}",
                        sourceFile = if (gDeep != null && gDeep.apkPath != "UNKNOWN") gDeep.apkPath else "raw/dumpsys_overlay.txt",
                        category = "RRO OVERLAYS",
                        title = pkg,
                        romEvidence = "Absent on ROM",
                        gsiEvidence = "[x] ENABLED" + (gDeep?.let { "\nAPK=${it.apkPath} | target=${it.targetPackage}" }.orEmpty()),
                        impact = if (language == AppLanguage.FR) {
                            "Overlay Treble/GSI activé côté GSI uniquement : vérifier les coordonnées et flags HBM."
                        } else {
                            "GSI-only enabled overlay: verify UDFPS sensor coordinates & HBM flags."
                        },
                        status = EvidenceStatus.OBSERVED,
                        knowledgeLevel = KnowledgeLevel.FACT
                    )
                }
            }
        }
    }

    private fun diffDumpsysBiometricAndDisplay(
        romZip: RawZipArchiveBundle,
        gsiZip: RawZipArchiveBundle,
        diffs: MutableList<PortFileDiffItem>,
        language: AppLanguage
    ) {
        // 1. Structured fingerprint & biometric dumpsys comparison
        val bioPairs = listOf(
            "raw/dumpsys_fingerprint.txt" to Regex("(sensor|udfps|fod|type=|supports|strength|resetLockout|acquired|hal).*", RegexOption.IGNORE_CASE),
            "raw/dumpsys_biometric.txt" to Regex("(sensor|modality|authenticator|strength|udfps|fod).*", RegexOption.IGNORE_CASE)
        )
        bioPairs.forEach { (file, kw) ->
            val rLines = extractKeyLines(readRaw(romZip, file), kw)
            val gLines = extractKeyLines(readRaw(gsiZip, file), kw)
            if (rLines.isEmpty() && gLines.isEmpty()) return@forEach
            val onlyRom = rLines.filter { it !in gLines }.take(12)
            val onlyGsi = gLines.filter { it !in rLines }.take(12)
            if (onlyRom.isNotEmpty() || onlyGsi.isNotEmpty()) {
                diffs += PortFileDiffItem(
                    id = "dump_${file.hashCode()}",
                    sourceFile = file,
                    category = "DUMPSYS SERVICES",
                    title = "${file.substringAfterLast('/')} structural delta",
                    romEvidence = onlyRom.joinToString("\n").ifBlank { "(identical or none unique)" },
                    gsiEvidence = onlyGsi.joinToString("\n").ifBlank { "(missing ROM signatures)" },
                    impact = if (language == AppLanguage.FR) {
                        "Divergence d'état capteur biométrique / UDFPS dans $file."
                    } else {
                        "Biometric/UDFPS sensor state divergence inside $file."
                    },
                    status = if (onlyRom.isNotEmpty()) EvidenceStatus.FAILED else EvidenceStatus.SUSPECT,
                    knowledgeLevel = KnowledgeLevel.FACT
                )
            }
        }

        // 2. Display & SurfaceFlinger structural signals (strictly stripping Brightness floats, StablePhysical addresses, DisplayCutout, dates)
        listOf(
            "raw/dumpsys_display.txt" to true,
            "raw/dumpsys_surfaceflinger.txt" to false
        ).forEach { (file, isDisplay) ->
            val rSignals = extractStructuredDisplaySignals(readRaw(romZip, file), isDisplay)
            val gSignals = extractStructuredDisplaySignals(readRaw(gsiZip, file), isDisplay)
            if (rSignals.isEmpty() && gSignals.isEmpty()) return@forEach

            val onlyRom = rSignals.filter { it !in gSignals }.take(12)
            val onlyGsi = gSignals.filter { it !in rSignals }.take(12)
            if (onlyRom.isNotEmpty() || onlyGsi.isNotEmpty()) {
                diffs += PortFileDiffItem(
                    id = "dump_struct_${file.hashCode()}",
                    sourceFile = file,
                    category = "DISPLAY / HBM PIPELINE",
                    title = "${file.substringAfterLast('/')} (HBM / ColorMode / FOD Layers)",
                    romEvidence = onlyRom.joinToString("\n").ifBlank { "(none unique)" },
                    gsiEvidence = onlyGsi.joinToString("\n").ifBlank { "(missing ROM HBM/ColorMode/Layer signals)" },
                    impact = if (language == AppLanguage.FR) {
                        "Divergence réelle HBM / ColorMode / Calque FOD dans $file (bruit Brightness/Adresse/Cutout filtré)."
                    } else {
                        "True HBM / ColorMode / FOD layer divergence in $file (Brightness/Address/Cutout noise stripped)."
                    },
                    status = if (onlyRom.any { it.contains("hbm", true) || it.contains("udfps", true) || it.contains("fod", true) || it.contains("color", true) }) {
                        EvidenceStatus.FAILED
                    } else {
                        EvidenceStatus.SUSPECT
                    },
                    knowledgeLevel = KnowledgeLevel.FACT
                )
            }
        }
    }

    internal fun extractStructuredDisplaySignals(raw: String, isDisplayDumpsys: Boolean): List<String> {
        if (raw.isBlank()) return emptyList()
        val noiseTokenRegex = Regex(
            "(^(Display\\s+)?(Brightness|SdrBrightness)=|mBrightnessState=|brightnessMinimum|brightnessMaximum|brightnessDefault|brightnessDim|hdrSdrRatio|address\\s+StablePhysical|address\\s*\\{|uniqueId=|DisplayCutout|cutoutPathParserInfo|RoundedCorners|deviceProductInfo|ManufactureDate|frameRateOverride|appVsyncOff|presDeadline|vsync=|mSequence=|mLastObserved|mActualBacklight|mTargetBacklight|timestamp)",
            RegexOption.IGNORE_CASE
        )
        val fodDisplayRegex = Regex(
            "(hbm|lhbm|udfps|fod|dimlayer|dim\\s*layer|colormode|supportedcolormodes|supportedhdrtypes|high_brightness|highbrightness|mactivecolormode|fingerprint|biometric|maxluminance)",
            RegexOption.IGNORE_CASE
        )

        val out = linkedSetOf<String>()
        raw.lineSequence().forEach { rawLine ->
            val trimmed = rawLine.trim()
            if (trimmed.isEmpty()) return@forEach

            // Break long single-line dumps (like DisplayDeviceInfo{...}) into atomic key=value tokens
            val fragments = if (trimmed.length > 180) {
                trimmed.split(Regex(",\\s+|\\s+\\|\\s+|;\\s+"))
            } else {
                listOf(trimmed)
            }

            for (frag in fragments) {
                val clean = frag.trim().removePrefix("{").removeSuffix("}")
                if (clean.length !in 4..200) continue
                if (noiseTokenRegex.containsMatchIn(clean)) continue
                if (isDisplayDumpsys && (clean.contains("DisplayDeviceInfo", true) && clean.length > 140)) continue
                if (fodDisplayRegex.containsMatchIn(clean)) {
                    out += clean
                }
            }
        }
        return out.take(120)
    }

    private fun diffHalAndBinderLayer(
        romZip: RawZipArchiveBundle,
        gsiZip: RawZipArchiveBundle,
        diffs: MutableList<PortFileDiffItem>,
        noise: MutableList<PortFileDiffItem>,
        language: AppLanguage
    ) {
        val kw = Regex("(fingerprint|biometric|fod|udfps|displayfeature|touchfeature|surfacecomposer|goodix)", RegexOption.IGNORE_CASE)
        listOf("raw/lshal.txt", "raw/vintf_manifests.txt", "raw/service_list.txt").forEach { file ->
            val rLines = extractKeyLines(readRaw(romZip, file), kw)
            val gLines = extractKeyLines(readRaw(gsiZip, file), kw)
            val onlyRom = rLines.filter { it !in gLines }
            val onlyGsi = gLines.filter { it !in rLines }
            if (onlyRom.isEmpty() && onlyGsi.isEmpty()) {
                if (rLines.isNotEmpty()) {
                    noise += PortFileDiffItem(
                        id = "hal_eq_${file.hashCode()}",
                        sourceFile = file,
                        category = "HAL_PARITY",
                        title = "${file.substringAfterLast('/')} identical",
                        romEvidence = "${rLines.size} interfaces match",
                        gsiEvidence = "${gLines.size} interfaces match",
                        impact = "HAL/Binder interfaces identical between ROM and GSI",
                        status = EvidenceStatus.CONFIRMED,
                        knowledgeLevel = KnowledgeLevel.FACT
                    )
                }
            } else {
                diffs += PortFileDiffItem(
                    id = "hal_diff_${file.hashCode()}",
                    sourceFile = file,
                    category = "HAL / VINTF / BINDER",
                    title = "${file.substringAfterLast('/')} divergence",
                    romEvidence = onlyRom.take(10).joinToString("\n").ifBlank { "(none unique)" },
                    gsiEvidence = onlyGsi.take(10).joinToString("\n").ifBlank { "(missing ROM HAL registration)" },
                    impact = if (language == AppLanguage.FR) {
                        "Écart d'enregistrement ou de liaison HIDL/AIDL entre Custom ROM et GSI sur le même /vendor."
                    } else {
                        "HIDL/AIDL binding or service visibility gap between Custom ROM and GSI on same /vendor."
                    },
                    status = EvidenceStatus.FAILED,
                    knowledgeLevel = KnowledgeLevel.FACT
                )
            }
        }
    }

    private fun diffInitSysfsAndSelinux(
        romZip: RawZipArchiveBundle,
        gsiZip: RawZipArchiveBundle,
        diffs: MutableList<PortFileDiffItem>,
        noise: MutableList<PortFileDiffItem>,
        language: AppLanguage
    ) {
        // init.rc delta
        val rInit = readRaw(romZip, "raw/init_rc_snippets.txt").lines().map { it.trim() }.filter { it.isNotBlank() }.toSet()
        val gInit = readRaw(gsiZip, "raw/init_rc_snippets.txt").lines().map { it.trim() }.filter { it.isNotBlank() }.toSet()
        val onlyRomInit = rInit - gInit
        val onlyGsiInit = gInit - rInit
        if (onlyRomInit.isNotEmpty() || onlyGsiInit.isNotEmpty()) {
            diffs += PortFileDiffItem(
                id = "init_rc_delta",
                sourceFile = "raw/init_rc_snippets.txt",
                category = "INIT.RC TRIGGERS",
                title = "System/Vendor Init.rc FOD entries delta",
                romEvidence = onlyRomInit.take(12).joinToString("\n").ifBlank { "(none unique)" },
                gsiEvidence = onlyGsiInit.take(12).joinToString("\n").ifBlank { "(none unique)" },
                impact = if (language == AppLanguage.FR) {
                    "Règles init.rc (chown/chmod sysfs, services FOD) différentes."
                } else {
                    "Init.rc FOD/sysfs trigger or service differences."
                },
                status = if (onlyRomInit.isNotEmpty()) EvidenceStatus.SUSPECT else EvidenceStatus.OBSERVED,
                knowledgeLevel = KnowledgeLevel.FACT
            )
        }

        // GSI-unique SELinux AVC denials (excluding AVC lines already tolerated on working Custom ROM!)
        val rAvc = readRaw(romZip, "raw/selinux_denials.txt").lines()
            .filter { it.contains("avc: denied", true) }
            .map { normalizeAvc(it) }
            .toHashSet()
        val gAvcRaw = readRaw(gsiZip, "raw/selinux_denials.txt").lines()
            .filter { it.contains("avc: denied", true) }
        val gsiUniqueAvc = mutableListOf<String>()
        gAvcRaw.forEach { line ->
            val norm = normalizeAvc(line)
            if (norm in rAvc) {
                noise += PortFileDiffItem(
                    id = "avc_shared_${norm.hashCode()}",
                    sourceFile = "raw/selinux_denials.txt",
                    category = "SHARED_AVC_NOISE",
                    title = "Shared SELinux AVC (${norm.take(50)})",
                    romEvidence = "Already occurs on working ROM",
                    gsiEvidence = line.take(140),
                    impact = "Present on working Custom ROM -> proven non-blocking",
                    status = EvidenceStatus.OBSERVED,
                    knowledgeLevel = KnowledgeLevel.CORRELATION
                )
            } else {
                gsiUniqueAvc += line
            }
        }
        if (gsiUniqueAvc.isNotEmpty()) {
            diffs += PortFileDiffItem(
                id = "avc_gsi_only",
                sourceFile = "raw/selinux_denials.txt",
                category = "SELINUX AVC (GSI-ONLY)",
                title = "${gsiUniqueAvc.size} AVC denial(s) unique to GSI",
                romEvidence = "0 matching denial(s) on working ROM",
                gsiEvidence = gsiUniqueAvc.distinct().take(10).joinToString("\n"),
                impact = if (language == AppLanguage.FR) {
                    "Refus SELinux absents sur la Custom ROM qui fonctionne : bloque potentiellement l'accès système au HAL/sysfs/display."
                } else {
                    "SELinux denials absent on working ROM: likely blocking system access to HAL/sysfs/display."
                },
                status = EvidenceStatus.FAILED,
                knowledgeLevel = KnowledgeLevel.FACT
            )
        }
    }

    private fun diffLiveExecutionAndLogs(
        romZip: RawZipArchiveBundle,
        gsiZip: RawZipArchiveBundle,
        diffs: MutableList<PortFileDiffItem>,
        noise: MutableList<PortFileDiffItem>,
        language: AppLanguage
    ) {
        val romRep = romZip.report
        val gsiRep = gsiZip.report
        if (romRep != null && gsiRep != null) {
            val comp = FodComparatorEngine.compare(romRep, gsiRep, language)
            comp.trueGsiBlockers.forEach { blk ->
                diffs += PortFileDiffItem(
                    id = "live_blk_${blk.title.hashCode()}",
                    sourceFile = "report.json / live_diff",
                    category = "LIVE EXECUTION & SYSFS",
                    title = blk.title,
                    romEvidence = blk.romDetail,
                    gsiEvidence = blk.gsiDetail,
                    impact = blk.impact,
                    status = blk.status,
                    knowledgeLevel = blk.knowledgeLevel
                )
            }
            comp.sharedNonBlockingItems.forEach { n ->
                noise += PortFileDiffItem(
                    id = "live_noise_${n.title.hashCode()}",
                    sourceFile = "report.json",
                    category = "SHARED_NON_BLOCKER",
                    title = n.title,
                    romEvidence = n.romDetail,
                    gsiEvidence = n.gsiDetail,
                    impact = n.impact,
                    status = n.status,
                    knowledgeLevel = n.knowledgeLevel
                )
            }
        }

        // Compare raw enrollment logs directly for key HAL callbacks (extCmd, onFingerDown, onAcquired, disp_param, lhbm, fod)
        val callbackRegex = Regex("(onFingerDown|onFingerUp|onAcquired|onEnrollResult|onError|extCmd|fod_press|disp_param|setHbm|setLhbm|udfps)", RegexOption.IGNORE_CASE)
        val rCalls = extractKeyLines(readRaw(romZip, "raw/logcat_enrollment.txt"), callbackRegex)
        val gCalls = extractKeyLines(readRaw(gsiZip, "raw/logcat_enrollment.txt"), callbackRegex)
        val missingCallbacks = rCalls.filter { rLine ->
            val key = callbackRegex.find(rLine)?.value?.lowercase().orEmpty()
            key.isNotEmpty() && gCalls.none { it.contains(key, true) }
        }.distinct().take(12)

        if (missingCallbacks.isNotEmpty()) {
            diffs += PortFileDiffItem(
                id = "logcat_missing_callbacks",
                sourceFile = "raw/logcat_enrollment.txt",
                category = "LIVE LOGCAT CALLBACKS",
                title = "HAL/UDFPS callbacks seen on ROM but missing in GSI enrollment log",
                romEvidence = missingCallbacks.joinToString("\n"),
                gsiEvidence = if (gCalls.isEmpty()) "(0 matching FOD callbacks in GSI logcat)" else gCalls.take(8).joinToString("\n"),
                impact = if (language == AppLanguage.FR) {
                    "Preuve directe dans raw/logcat_enrollment.txt : la séquence ROM déclenche ces appels alors que la GSI ne les émet pas."
                } else {
                    "Direct proof in raw/logcat_enrollment.txt: ROM triggers these callbacks while GSI does not emit them."
                },
                status = EvidenceStatus.FAILED,
                knowledgeLevel = KnowledgeLevel.FACT
            )
        }
    }

    private fun diffElfDisassembly(
        romZip: RawZipArchiveBundle,
        gsiZip: RawZipArchiveBundle,
        diffs: MutableList<PortFileDiffItem>,
        language: AppLanguage
    ) {
        val rElf = readRaw(romZip, "disassembly/elf_disassembly_full.txt")
        val gElf = readRaw(gsiZip, "disassembly/elf_disassembly_full.txt")
        if (rElf.isBlank() && gElf.isBlank()) return
        val elfSignalRegex = Regex("(BINARY:|DT_NEEDED:|extCmd|onFingerDown|fod|udfps|hbm|lhbm|disp_param|xiaomi|oplus|goodix)", RegexOption.IGNORE_CASE)
        val rSignals = extractKeyLines(rElf, elfSignalRegex)
        val gSignals = extractKeyLines(gElf, elfSignalRegex)
        val diffSignals = rSignals.filter { it !in gSignals }.take(14)
        if (diffSignals.isNotEmpty()) {
            diffs += PortFileDiffItem(
                id = "elf_signal_diff",
                sourceFile = "disassembly/elf_disassembly_full.txt",
                category = "ELF BINARIES & SYMBOLS",
                title = "ELF / Symbol / String references differing across archives",
                romEvidence = diffSignals.joinToString("\n"),
                gsiEvidence = gSignals.take(10).joinToString("\n").ifBlank { "(absent)" },
                impact = if (language == AppLanguage.FR) {
                    "Chaînes/symboles FOD attendus par les binaires HAL (sans modification vendor : la GSI doit envoyer ces commandes)."
                } else {
                    "FOD symbols/strings used by HAL binaries (untouched vendor expects these calls from GSI)."
                },
                status = EvidenceStatus.OBSERVED,
                knowledgeLevel = KnowledgeLevel.FACT
            )
        }
    }

    private fun diffLiveProcMapsAndDexSources(
        romZip: RawZipArchiveBundle,
        gsiZip: RawZipArchiveBundle,
        diffs: MutableList<PortFileDiffItem>,
        language: AppLanguage
    ) {
        val rProc = readRaw(romZip, "raw/proc_live_maps.txt")
        val gProc = readRaw(gsiZip, "raw/proc_live_maps.txt")
        if (rProc.isNotBlank() && !rProc.startsWith("PROC_MAPS_UNAVAILABLE")) {
            val mapRegex = Regex("^(FOD_MATCH|MAPPED_APK|MAPPED_JAR|ENROLL_NEW_MAP|ENROLL_NEW_FD):\\s*(.+)$")
            val rItems = rProc.lineSequence().mapNotNull { mapRegex.matchEntire(it.trim())?.groupValues?.get(2)?.trim() }.distinct().toList()
            val gItems = gProc.lineSequence().mapNotNull { mapRegex.matchEntire(it.trim())?.groupValues?.get(2)?.trim() }.distinct().toHashSet()
            val uniqueRomMaps = rItems.filter { item ->
                item !in gItems && (item.contains("overlay", true) || item.contains("fod", true) || item.contains("udfps", true) ||
                    item.contains("fingerprint", true) || item.contains("biometric", true) || item.contains("hbm", true) ||
                    item.contains("disp_param", true) || item.contains("/sys/", true))
            }.take(16)
            if (uniqueRomMaps.isNotEmpty()) {
                diffs += PortFileDiffItem(
                    id = "proc_maps_unique_rom",
                    sourceFile = "raw/proc_live_maps.txt",
                    category = "LIVE /proc/<pid>/maps",
                    title = "Fichiers/FD FOD réellement mappés dans les processus ROM mais absents sur GSI",
                    romEvidence = uniqueRomMaps.joinToString("\n"),
                    gsiEvidence = if (gProc.isBlank()) "(raw/proc_live_maps.txt absent)" else "${gItems.size} entrées mappées GSI (sans ces chemins)",
                    impact = if (language == AppLanguage.FR) {
                        "Preuve noyau directe (/proc/<pid>/maps & fd) des APK/JAR/sysfs réellement chargés en mémoire pendant l'enrôlement ROM."
                    } else {
                        "Direct kernel proof (/proc/<pid>/maps & fd) of APKs/JARs/sysfs actually loaded in RAM during working ROM enrollment."
                    },
                    status = EvidenceStatus.FAILED,
                    knowledgeLevel = KnowledgeLevel.FACT
                )
            }
        }

        val rDex = readRaw(romZip, "raw/dex_source_extract.txt")
        val gDex = readRaw(gsiZip, "raw/dex_source_extract.txt")
        if (rDex.isNotBlank()) {
            val dexLineRegex = Regex("^(CLASS|METHOD|STRING|RES_KEY|TRACE_METHOD|TRACE_RES|TRACE_CALL):\\s*(.+)$")
            val rDexLines = rDex.lineSequence().mapNotNull { line ->
                val t = line.trim()
                if (dexLineRegex.matches(t)) t else null
            }.distinct().toList()
            val gDexLines = gDex.lineSequence().map { it.trim() }.toHashSet()
            val uniqueRomHooks = rDexLines.filter { it !in gDexLines }.take(24)
            if (uniqueRomHooks.isNotEmpty()) {
                diffs += PortFileDiffItem(
                    id = "dex_hooks_unique_rom",
                    sourceFile = "raw/dex_source_extract.txt",
                    category = "DEX SOURCE HOOKS",
                    title = "Classes/Méthodes/Bytecode FOD extraits du code DEX/VDEX ROM absents sur GSI",
                    romEvidence = uniqueRomHooks.joinToString("\n"),
                    gsiEvidence = if (gDex.isBlank()) "(raw/dex_source_extract.txt absent)" else "Hooks manquants dans SystemUI/Framework GSI",
                    impact = if (language == AppLanguage.FR) {
                        "Code source DEX/VDEX réel (SystemUI / services.jar / APEX biométrique) et appels R.id UDFPS/HBM/extCmd sur la Custom ROM."
                    } else {
                        "Actual DEX/VDEX bytecode hooks (SystemUI / services.jar / biometric APEX) and UDFPS/HBM/extCmd R.id references in Custom ROM."
                    },
                    status = EvidenceStatus.FAILED,
                    knowledgeLevel = KnowledgeLevel.FACT
                )
            }
        }

        val rBinder = readRaw(romZip, "raw/binder_trace_delta.txt")
        val gBinder = readRaw(gsiZip, "raw/binder_trace_delta.txt")
        if (rBinder.isNotBlank() && !rBinder.startsWith("BINDER_TRACE_UNAVAILABLE")) {
            val binderRegex = Regex("^(PEER|TX):\\s*(.+)$")
            val rLinks = rBinder.lineSequence().mapNotNull { binderRegex.matchEntire(it.trim())?.value }.distinct().toList()
            val gLinks = gBinder.lineSequence().map { it.trim() }.toHashSet()
            val onlyRomBinder = rLinks.filter { it !in gLinks }.take(16)
            if (onlyRomBinder.isNotEmpty()) {
                diffs += PortFileDiffItem(
                    id = "binder_ipc_unique_rom",
                    sourceFile = "raw/binder_trace_delta.txt",
                    category = "BINDER IPC / HAL LINKS",
                    title = "Liens Binder IPC & Transactions HAL observés sur ROM mais absents sur GSI",
                    romEvidence = onlyRomBinder.joinToString("\n"),
                    gsiEvidence = if (gBinder.isBlank()) "(raw/binder_trace_delta.txt absent)" else "${gLinks.size} lignes Binder GSI sans ces liens",
                    impact = if (language == AppLanguage.FR) {
                        "Transactions Binder entre SystemUI/system_server et le HAL vendor manquantes côté GSI."
                    } else {
                        "Binder IPC links between SystemUI/system_server and vendor HAL missing on GSI."
                    },
                    status = EvidenceStatus.FAILED,
                    knowledgeLevel = KnowledgeLevel.FACT
                )
            }
        }
    }

    private fun diffProvenanceArtifacts(
        romProv: List<FileProvenanceArtifact>,
        gsiProv: List<FileProvenanceArtifact>,
        diffs: MutableList<PortFileDiffItem>,
        language: AppLanguage
    ) {
        if (romProv.isEmpty() && gsiProv.isEmpty()) return
        val gsiByPath = gsiProv.associateBy { it.filePath }
        val gsiByFileName = gsiProv.groupBy { it.filePath.substringAfterLast('/') }

        for (rItem in romProv) {
            if (rItem.category == "OVERLAY_APK") continue // already covered with full details in diffOverlayFiles
            val gExact = gsiByPath[rItem.filePath]
            val gMatch = gExact ?: gsiByFileName[rItem.filePath.substringAfterLast('/')]?.firstOrNull()
            if (gMatch == null) {
                val isSystemPartition = !rItem.filePath.startsWith("/vendor/") && !rItem.filePath.startsWith("/odm/")
                diffs += PortFileDiffItem(
                    id = "prov_miss_${rItem.id.hashCode()}",
                    sourceFile = rItem.filePath,
                    category = "FILE PROVENANCE (${rItem.category})",
                    title = "${rItem.filePath} (${rItem.directory})",
                    romEvidence = rItem.importantContents.take(8).joinToString(" | ").ifBlank { rItem.matchedSymbolOrKey },
                    gsiEvidence = if (language == AppLanguage.FR) "ABSENT sur GSI" else "ABSENT on GSI",
                    impact = if (isSystemPartition) {
                        if (language == AppLanguage.FR) {
                            "Fichier système/product FOD présent sur ROM (${rItem.filePath}) mais absent côté GSI."
                        } else {
                            "System/product FOD file present on ROM (${rItem.filePath}) yet missing on GSI."
                        }
                    } else {
                        if (language == AppLanguage.FR) {
                            "Fichier partition vendor/odm lu sur ROM ; vendor intact mais ses propriétés/règles doivent être reflétées côté GSI."
                        } else {
                            "Vendor/odm artifact read on ROM; keep vendor untouched and mirror required interface/props on GSI."
                        }
                    },
                    status = if (isSystemPartition) EvidenceStatus.FAILED else EvidenceStatus.OBSERVED,
                    knowledgeLevel = KnowledgeLevel.FACT
                )
            } else {
                val rSet = rItem.importantContents.toSet()
                val gSet = gMatch.importantContents.toSet()
                val onlyRomLines = (rSet - gSet).take(8)
                if (onlyRomLines.isNotEmpty()) {
                    diffs += PortFileDiffItem(
                        id = "prov_diff_${rItem.id.hashCode()}",
                        sourceFile = rItem.filePath,
                        category = "FILE PROVENANCE (${rItem.category})",
                        title = "Delta interne : ${rItem.filePath}",
                        romEvidence = onlyRomLines.joinToString(" | "),
                        gsiEvidence = gMatch.importantContents.take(6).joinToString(" | ").ifBlank { "(empty)" },
                        impact = if (language == AppLanguage.FR) {
                            "Entrées internes présentes dans ${rItem.filePath} sur Custom ROM mais absentes/différentes dans ${gMatch.filePath} sur GSI."
                        } else {
                            "Internal entries present in ROM ${rItem.filePath} yet missing/different in GSI ${gMatch.filePath}."
                        },
                        status = EvidenceStatus.SUSPECT,
                        knowledgeLevel = KnowledgeLevel.FACT
                    )
                }
            }
        }
    }

    private fun buildExtractableFiles(
        romZip: RawZipArchiveBundle,
        gsiZip: RawZipArchiveBundle,
        romOverlays: Map<String, OverlayDeepInspection>,
        gsiOverlays: Map<String, OverlayDeepInspection>,
        romProvenance: List<FileProvenanceArtifact>,
        gsiProvenance: List<FileProvenanceArtifact>,
        diffs: List<PortFileDiffItem>,
        language: AppLanguage
    ): List<ExtractableFileItem> {
        val items = mutableListOf<ExtractableFileItem>()

        // 1. Missing/Inactive active RRO Overlay APKs (ranked strictly by content fodRelevanceScore & lookupWinners!)
        val rroDiffs = diffs.filter { it.category == "RRO OVERLAYS" && it.romEvidence.contains("ENABLED", true) }
            .sortedByDescending { romOverlays[it.title]?.fodRelevanceScore ?: 0 }
        rroDiffs.forEach { d ->
            val pkg = d.title
            val deep = romOverlays[pkg]
            val apkPath = deep?.apkPath?.takeIf { it != "UNKNOWN" }
            val dir = deep?.directory?.takeIf { it != "UNKNOWN" }
            val fileName = apkPath?.substringAfterLast('/') ?: "${pkg.substringAfterLast('.')}.apk"
            val targetPath = when {
                apkPath != null && (apkPath.startsWith("/product/") || apkPath.startsWith("/system_ext/") || apkPath.startsWith("/system/")) -> apkPath
                else -> "/product/overlay/$fileName"
            }
            val contents = buildList {
                if (deep != null) {
                    add("SCORE=${deep.fodRelevanceScore} | liveMapped=${deep.provenInLiveMaps} | targetPackage=${deep.targetPackage} | static=${deep.isStatic} | priority=${deep.priority}")
                    deep.lookupWinners.forEach { add("LOOKUP WINNER: $it") }
                    deep.decodedArscEntries.take(25).forEach { add(it) }
                    addAll(deep.manifestSummary.take(6))
                    addAll(deep.fodConfigEntries.take(20))
                    if (deep.pseudoXmlSource.isNotBlank()) {
                        add("--- Decoded Pseudo-XML ---")
                        addAll(deep.pseudoXmlSource.lineSequence().take(18).toList())
                    }
                } else {
                    add(
                        if (language == AppLanguage.FR) {
                            "Archive ROM antérieure sans overlay_deep_inspect.txt — relancez ANALYSE sur Custom ROM pour extraire l'APK exact et ses clés ARSC/XML."
                        } else {
                            "Legacy ROM archive lacks overlay_deep_inspect.txt — re-run ANALYSE on Custom ROM to resolve exact APK path & ARSC/XML keys."
                        }
                    )
                }
            }
            val score = deep?.fodRelevanceScore ?: 0
            val isProvenFod = score >= 40 || (deep?.lookupWinners?.isNotEmpty() == true) ||
                pkg.contains("fod", true) || pkg.contains("udfps", true) || pkg.contains("fingerprint", true)

            items += ExtractableFileItem(
                id = "ext_rro_${pkg.hashCode()}",
                category = "RRO_OVERLAY_APK",
                title = pkg,
                romFilePath = apkPath ?: (if (language == AppLanguage.FR) "Non résolu dans ce ZIP ($pkg — relancer ANALYSE v2)" else "Unresolved in legacy ZIP ($pkg)"),
                romDirectory = dir ?: "/product/overlay ou /system_ext/overlay",
                targetGsiPath = targetPath,
                importantElements = contents.distinct(),
                missingMechanism = if (language == AppLanguage.FR) {
                    "Score FOD=${score}${if (deep?.provenInLiveMaps == true) " [Prouvé live /proc]" else ""} — Fournit la surcharge RRO active vers ${deep?.targetPackage?.ifBlank { "SystemUI/Framework" } ?: "SystemUI/Framework"} (coordonnées capteur UDFPS, nœud sysfs/HBM, booléens config_udfps*)."
                } else {
                    "FOD Score=${score}${if (deep?.provenInLiveMaps == true) " [Proven live /proc]" else ""} — Provides active RRO overrides for ${deep?.targetPackage?.ifBlank { "SystemUI/Framework" } ?: "SystemUI/Framework"} (UDFPS sensor props, HBM sysfs node, config_udfps* booleans)."
                },
                gsiCurrentState = d.gsiEvidence,
                priorityPercent = when {
                    score >= 80 -> 99
                    score >= 40 -> 96
                    isProvenFod -> 93
                    else -> 78
                },
                canExtractWithoutVendorOrBoot = true
            )
        }

        // 2. .prop provenance files containing missing/divergent FOD/Display properties
        val romPropFiles = romProvenance.filter { it.category == "PROP_FILE" }
        val propDiffs = diffs.filter { it.category == "PROPERTIES (getprop)" && (it.status == EvidenceStatus.FAILED || it.status == EvidenceStatus.SUSPECT) }
        if (propDiffs.isNotEmpty()) {
            if (romPropFiles.isNotEmpty()) {
                romPropFiles.forEach { pf ->
                    val matchingDiffs = propDiffs.filter { d ->
                        pf.importantContents.any { line -> line.contains(d.title) }
                    }
                    if (matchingDiffs.isNotEmpty() || pf.filePath.startsWith("/product") || pf.filePath.startsWith("/system")) {
                        val important = (matchingDiffs.map { "${it.romEvidence} (GSI: ${it.gsiEvidence})" } + pf.importantContents).distinct().take(18)
                        val targetGsi = if (pf.filePath.startsWith("/vendor") || pf.filePath.startsWith("/odm")) {
                            "/system_ext/etc/build.prop (ou Magisk system.prop — vendor/boot intacts)"
                        } else {
                            pf.filePath
                        }
                        items += ExtractableFileItem(
                            id = "ext_prop_${pf.filePath.hashCode()}",
                            category = "PROP_FILE",
                            title = pf.filePath.substringAfterLast('/'),
                            romFilePath = pf.filePath,
                            romDirectory = pf.directory,
                            targetGsiPath = targetGsi,
                            importantElements = important,
                            missingMechanism = if (language == AppLanguage.FR) {
                                "Déclare les propriétés FOD / HBM / capteur optique manquantes ou divergentes côté GSI."
                            } else {
                                "Defines FOD / HBM / optical sensor system properties missing or divergent on GSI."
                            },
                            gsiCurrentState = "${matchingDiffs.size} prop(s) divergentes",
                            priorityPercent = if (matchingDiffs.any { it.status == EvidenceStatus.FAILED }) 90 else 76,
                            canExtractWithoutVendorOrBoot = true
                        )
                    }
                }
            } else {
                // Legacy fallback: group missing critical properties even if exact .prop file wasn't indexed
                val criticalProps = propDiffs.filter { it.status == EvidenceStatus.FAILED }.take(12)
                if (criticalProps.isNotEmpty()) {
                    items += ExtractableFileItem(
                        id = "ext_prop_legacy",
                        category = "PROP_FILE",
                        title = "Propriétés système FOD/Display manquantes",
                        romFilePath = "raw/getprop_all.txt (index .prop non capturé dans ce ZIP)",
                        romDirectory = "/product/etc/build.prop / /system_ext/etc/build.prop",
                        targetGsiPath = "/product/etc/build.prop ou module Magisk system.prop",
                        importantElements = criticalProps.map { "${it.romEvidence} [GSI=${it.gsiEvidence}]" },
                        missingMechanism = if (language == AppLanguage.FR) {
                            "Propriétés actives sur Custom ROM absentes de la GSI."
                        } else {
                            "Active Custom ROM properties absent on GSI."
                        },
                        gsiCurrentState = "${criticalProps.size} prop(s) [FAILED]",
                        priorityPercent = 86,
                        canExtractWithoutVendorOrBoot = true
                    )
                }
            }
        }

        // 3. Init.rc files on system/product/system_ext (or triggers from raw/init_rc_snippets.txt)
        val rInitRaw = readRaw(romZip, "raw/init_rc_snippets.txt")
        val gInitRaw = readRaw(gsiZip, "raw/init_rc_snippets.txt")
        val gInitLines = gInitRaw.lines().map { it.trim() }.filter { it.isNotBlank() }.toSet()
        val romInitByFile = rInitRaw.lineSequence()
            .map { it.trim() }
            .filter { it.startsWith("/") && it.contains(":") && it !in gInitLines }
            .groupBy { it.substringBefore(":") }

        romInitByFile.entries.take(10).forEach { (rcPath, lines) ->
            val cleanLines = lines.map { it.substringAfter(":").trim() }.distinct().take(15)
            val isSystemSide = rcPath.startsWith("/system") || rcPath.startsWith("/product") || rcPath.startsWith("/system_ext")
            items += ExtractableFileItem(
                id = "ext_rc_${rcPath.hashCode()}",
                category = "INIT_RC",
                title = rcPath.substringAfterLast('/'),
                romFilePath = rcPath,
                romDirectory = rcPath.substringBeforeLast('/'),
                targetGsiPath = if (isSystemSide) rcPath else "/system_ext/etc/init/fod_port_triggers.rc (sans toucher /vendor)",
                importantElements = cleanLines,
                missingMechanism = if (language == AppLanguage.FR) {
                    "Initialise permissions sysfs FOD/HBM/Touch (chown/chmod), propriétés boot ou démons auxiliaires."
                } else {
                    "Initializes FOD/HBM/Touch sysfs permissions (chown/chmod), boot props, or helper services."
                },
                gsiCurrentState = "Règles absentes sur GSI",
                priorityPercent = if (isSystemSide) 88 else 68,
                canExtractWithoutVendorOrBoot = true
            )
        }

        // 4. Permissions / Sysconfig / DisplayConfig XML + SELinux policy files from FileProvenanceArtifact
        val gsiProvPaths = gsiProvenance.map { it.filePath }.toHashSet()
        romProvenance
            .filter { it.category in setOf("PERMISSIONS_XML", "DISPLAY_CONFIG", "SELINUX_POLICY") }
            .forEach { item ->
                val missingOnGsi = item.filePath !in gsiProvPaths
                if (!missingOnGsi) return@forEach
                val isSysSide = !item.filePath.startsWith("/vendor/") && !item.filePath.startsWith("/odm/")
                val targetGsi = if (isSysSide) item.filePath else when (item.category) {
                    "DISPLAY_CONFIG" -> "/product/etc/displayconfig/${item.filePath.substringAfterLast('/')}"
                    "SELINUX_POLICY" -> "/system_ext/etc/selinux/${item.filePath.substringAfterLast('/')}"
                    else -> "/product/etc/permissions/${item.filePath.substringAfterLast('/')}"
                }
                items += ExtractableFileItem(
                    id = "ext_prov_${item.id.hashCode()}",
                    category = item.category,
                    title = item.filePath.substringAfterLast('/'),
                    romFilePath = item.filePath,
                    romDirectory = item.directory,
                    targetGsiPath = targetGsi,
                    importantElements = item.importantContents.take(15),
                    missingMechanism = when (item.category) {
                        "DISPLAY_CONFIG" -> if (language == AppLanguage.FR) "Profil écran HBM / luminosité haute / seuils lux requis pour illumination FOD." else "Panel HBM / high-brightness displayconfig profile required for FOD illumination."
                        "SELINUX_POLICY" -> if (language == AppLanguage.FR) "Règles/contextes SELinux autorisant l'accès SystemUI/Framework aux nœuds sysfs & Binder HAL." else "SELinux policy/contexts allowing SystemUI/Framework access to sysfs & HAL Binder."
                        else -> if (language == AppLanguage.FR) "Déclaration XML de fonctionnalité biométrique / sysconfig / permission système." else "System biometric feature / sysconfig / permission XML declaration."
                    },
                    gsiCurrentState = if (isSysSide) "Absent sur GSI" else "Référence vendor intacte à miroiter côté système",
                    priorityPercent = if (isSysSide) 84 else 62,
                    canExtractWithoutVendorOrBoot = true
                )
            }

        // 5. SystemUI / Framework JAR/APK provenance when live callbacks / HBM transition stall OR DEX source hooks differ
        val hasStallOrCallbackLoss = diffs.any {
            it.category == "LIVE LOGCAT CALLBACKS" ||
                it.category == "DEX SOURCE HOOKS" ||
                (it.category == "LIVE EXECUTION & SYSFS" && (it.title.contains("HAL", true) || it.title.contains("Sysfs", true)))
        }
        val sysUiProv = romProvenance.filter { it.category == "SYSTEMUI_FRAMEWORK" }
        val romDexExtracts = loadDexSourceExtracts(romZip)
        if ((hasStallOrCallbackLoss || romDexExtracts.isNotEmpty()) && (sysUiProv.isNotEmpty() || romDexExtracts.isNotEmpty())) {
            sysUiProv.take(4).forEach { sp ->
                val matchingDex = romDexExtracts.firstOrNull { it.archivePath == sp.filePath }
                val dexElements = matchingDex?.let { dex ->
                    (dex.matchedClasses.take(8).map { "CLASS: $it" } +
                        dex.matchedMethods.take(12).map { "METHOD: $it" } +
                        dex.matchedStrings.take(6).map { "STRING: $it" })
                }.orEmpty()
                items += ExtractableFileItem(
                    id = "ext_sysfw_${sp.id.hashCode()}",
                    category = "SYSTEMUI_FRAMEWORK",
                    title = sp.filePath.substringAfterLast('/'),
                    romFilePath = sp.filePath,
                    romDirectory = sp.directory,
                    targetGsiPath = "${sp.filePath} (adapter UdfpsController / UdfpsDisplayMode / pont extCmd côté GSI)",
                    importantElements = (dexElements + sp.importantContents).distinct().take(24),
                    missingMechanism = if (language == AppLanguage.FR) {
                        "Contient le code source DEX UdfpsHandler / HBM / extension vendor (extCmd/onFingerDown) manquant dans le binaire GSI."
                    } else {
                        "Contains exact DEX UdfpsHandler / HBM / vendor extension bridge (extCmd/onFingerDown) missing in GSI binary."
                    },
                    gsiCurrentState = "Appels callbacks/HBM absents pendant l'enrôlement GSI",
                    priorityPercent = 94,
                    canExtractWithoutVendorOrBoot = true
                )
            }
            // Add any DEX extract whose archive path wasn't already covered by sysUiProv
            val coveredPaths = sysUiProv.map { it.filePath }.toHashSet()
            romDexExtracts.filter { it.archivePath !in coveredPaths }.take(4).forEach { dex ->
                items += ExtractableFileItem(
                    id = "ext_dex_${dex.archivePath.hashCode()}",
                    category = "SYSTEMUI_FRAMEWORK",
                    title = "${dex.archivePath.substringAfterLast('/')} (DEX Source)",
                    romFilePath = dex.archivePath,
                    romDirectory = dex.archivePath.substringBeforeLast('/'),
                    targetGsiPath = "${dex.archivePath} (porter classes/méthodes FOD côté GSI)",
                    importantElements = (dex.matchedClasses.take(8).map { "CLASS: $it" } +
                        dex.matchedMethods.take(12).map { "METHOD: $it" } +
                        dex.matchedStrings.take(6).map { "STRING: $it" }),
                    missingMechanism = if (language == AppLanguage.FR) {
                        "Extrait DEX (${dex.targetHint}) contenant les hooks Java/Kotlin FOD actifs sur Custom ROM."
                    } else {
                        "DEX source extract (${dex.targetHint}) holding working Custom ROM FOD hooks."
                    },
                    gsiCurrentState = "Code source FOD divergent / absent dans GSI",
                    priorityPercent = 93,
                    canExtractWithoutVendorOrBoot = true
                )
            }
        }

        // 6. Live /proc/<pid>/maps uniquely mapped ROM APK/JAR files (excluding vendor/boot)
        val procDiffs = diffs.filter { it.category == "LIVE /proc/<pid>/maps" }
        if (procDiffs.isNotEmpty()) {
            procDiffs.flatMap { it.romEvidence.lines() }
                .map { it.trim() }
                .filter { (it.startsWith("/product/") || it.startsWith("/system_ext/") || it.startsWith("/system/") || it.startsWith("/apex/")) && (it.endsWith(".apk", true) || it.endsWith(".jar", true)) }
                .distinct()
                .take(4)
                .forEach { mappedPath ->
                    items += ExtractableFileItem(
                        id = "ext_proc_${mappedPath.hashCode()}",
                        category = "LIVE_PROC_MAPPED_MODULE",
                        title = mappedPath.substringAfterLast('/'),
                        romFilePath = mappedPath,
                        romDirectory = mappedPath.substringBeforeLast('/'),
                        targetGsiPath = mappedPath,
                        importantElements = listOf("Mappé en mémoire pendant l'enrôlement FOD (/proc/<pid>/maps)", "Chemin exact: $mappedPath"),
                        missingMechanism = if (language == AppLanguage.FR) {
                            "Module réellement chargé par SystemUI / system_server pendant l'enrôlement ROM mais absent de la mémoire GSI."
                        } else {
                            "Module actively loaded in memory by SystemUI / system_server during ROM enrollment yet absent on GSI."
                        },
                        gsiCurrentState = "Non mappé dans les processus GSI",
                        priorityPercent = 91,
                        canExtractWithoutVendorOrBoot = true
                    )
                }
        }

        return items
            .distinctBy { "${it.category}::${it.romFilePath}::${it.title}" }
            .sortedByDescending { it.priorityPercent }
    }

    private fun buildRankedPortingSolutions(
        romZip: RawZipArchiveBundle,
        gsiZip: RawZipArchiveBundle,
        diffs: List<PortFileDiffItem>,
        extractables: List<ExtractableFileItem>,
        language: AppLanguage
    ): List<PortingCandidateSolution> {
        val solutions = mutableListOf<PortingCandidateSolution>()
        var rank = 1

        // Tier 1: Props / PHH / Treble Settings (zero Framework/SystemUI/Vendor edits)
        val propDiffs = diffs.filter { it.category == "PROPERTIES (getprop)" }
        if (propDiffs.isNotEmpty()) {
            val missingPhhOrFod = propDiffs.filter { it.status == EvidenceStatus.FAILED }
            val propFiles = extractables.filter { it.category == "PROP_FILE" }
            solutions += PortingCandidateSolution(
                id = "port_tier1_props",
                tier = PortingTier.PROPS_PHH_TREBLE,
                rank = rank++,
                title = if (language == AppLanguage.FR) {
                    "Niveau 1 : Injection des propriétés FOD/Display manquantes (system.prop / PHH Treble)"
                } else {
                    "Tier 1: Inject missing FOD/Display system properties (system.prop / PHH Treble)"
                },
                layer = "System Properties / product.prop / Treble Settings",
                requiresFrameworkOrSystemUi = false,
                confidencePercent = if (missingPhhOrFod.isNotEmpty()) 75 else 45,
                whyItApplies = if (language == AppLanguage.FR) {
                    "${propDiffs.size} propriété(s) liées au FOD/affichage/biométrie divergent dans raw/getprop_all.txt entre la ROM et la GSI."
                } else {
                    "${propDiffs.size} FOD/display/biometric properties diverge in raw/getprop_all.txt between ROM and GSI."
                },
                exactSourcesInZip = (propFiles.map { "${it.romFilePath} -> ${it.importantElements.take(3)}" } + propDiffs.take(6).map { "raw/getprop_all.txt -> ${it.title}: ROM=${it.romEvidence} | GSI=${it.gsiEvidence}" }).distinct().take(8),
                concreteActionSteps = propDiffs.filter { it.romEvidence.contains("=") }.take(6).map {
                    "Aligner côté /system_ext ou Magisk/resetprop : ${it.romEvidence}"
                }.ifEmpty {
                    listOf(
                        if (language == AppLanguage.FR) "Comparer chaque propriété divergente de raw/getprop_all.txt et aligner côté /product props ou Treble Settings."
                        else "Align divergent properties from raw/getprop_all.txt via /product props or Treble Settings."
                    )
                },
                limitations = if (language == AppLanguage.FR) {
                    "Insuffisant seul si le HAL vendor attend un appel Binder/AIDL ou un ioctl HBM que SystemUI/Framework GSI n'émet pas."
                } else {
                    "Insufficient alone if vendor HAL requires a Binder/AIDL extension call or HBM ioctl not dispatched by GSI SystemUI/Framework."
                }
            )
        }

        // Tier 2: RRO Overlays + Init.rc + System SELinux + Permissions/DisplayConfig XML (still zero Framework/SystemUI Java recompile!)
        val rroDiffs = diffs.filter { it.category == "RRO OVERLAYS" }
        val initDiffs = diffs.filter { it.category == "INIT.RC TRIGGERS" }
        val selinuxDiffs = diffs.filter { it.category == "SELINUX AVC (GSI-ONLY)" }
        val provDiffs = diffs.filter { it.category.startsWith("FILE PROVENANCE") }
        val rroExtractables = extractables.filter { it.category == "RRO_OVERLAY_APK" }
        if (rroDiffs.isNotEmpty() || initDiffs.isNotEmpty() || selinuxDiffs.isNotEmpty() || provDiffs.isNotEmpty()) {
            val sources = (
                rroExtractables.map { "${it.romFilePath} (dir=${it.romDirectory})" } +
                    (rroDiffs + initDiffs + selinuxDiffs + provDiffs).map { "${it.sourceFile} -> ${it.title}" }
                ).distinct().take(10)
            solutions += PortingCandidateSolution(
                id = "port_tier2_rro_selinux",
                tier = PortingTier.RRO_INIT_SELINUX_SYSTEM,
                rank = rank++,
                title = if (language == AppLanguage.FR) {
                    "Niveau 2 : Extraire overlays RRO exacts, XML display/permissions, triggers init & SELinux système"
                } else {
                    "Tier 2: Extract exact RRO overlays, display/permissions XMLs, init triggers & system SELinux rules"
                },
                layer = "RRO Overlay (/product/overlay) + system_ext/etc/init + sepolicy système",
                requiresFrameworkOrSystemUi = false,
                confidencePercent = if (rroDiffs.any { it.status == EvidenceStatus.FAILED } || selinuxDiffs.isNotEmpty()) 88 else 58,
                whyItApplies = if (language == AppLanguage.FR) {
                    "Les archives identifient ${rroDiffs.size} écart(s) d'overlay RRO actif (${rroExtractables.count { !it.romFilePath.startsWith("Non") }} APK localisé(s)), ${initDiffs.size} écart(s) init.rc, ${provDiffs.size} fichier(s) système et ${selinuxDiffs.size} refus AVC GSI."
                } else {
                    "Archives pinpoint ${rroDiffs.size} active RRO overlay diffs, ${initDiffs.size} init.rc diffs, ${provDiffs.size} system file diffs, and ${selinuxDiffs.size} GSI-only AVC denials."
                },
                exactSourcesInZip = sources,
                concreteActionSteps = buildList {
                    rroExtractables.take(3).forEach { ov ->
                        add(
                            if (language == AppLanguage.FR) "Extraire depuis Custom ROM `${ov.romFilePath}` (répertoire `${ov.romDirectory}`) vers `${ov.targetGsiPath}`."
                            else "Extract `${ov.romFilePath}` from Custom ROM (dir `${ov.romDirectory}`) to GSI `${ov.targetGsiPath}`."
                        )
                    }
                    extractables.filter { it.category in setOf("INIT_RC", "DISPLAY_CONFIG", "PERMISSIONS_XML", "SELINUX_POLICY") }.take(4).forEach { ex ->
                        add(
                            if (language == AppLanguage.FR) "Porter `[${ex.category}]` depuis `${ex.romFilePath}` vers `${ex.targetGsiPath}`."
                            else "Port `[${ex.category}]` from `${ex.romFilePath}` to `${ex.targetGsiPath}`."
                        )
                    }
                    if (isEmpty() && rroDiffs.isNotEmpty()) {
                        add(
                            if (language == AppLanguage.FR) "Porter l'overlay RRO actif (${rroDiffs.first().title}) dans /product/overlay/ côté GSI."
                            else "Port active RRO overlay (${rroDiffs.first().title}) into GSI /product/overlay/."
                        )
                    }
                },
                limitations = if (language == AppLanguage.FR) {
                    "Garde boot et vendor 100 % intacts et ne recompile pas le Framework, mais ne crée pas de nouveau callback JNI/HIDL s'il est codé en dur dans SystemUI."
                } else {
                    "Keeps boot and vendor 100% untouched without Framework recompilation, but cannot add missing native/HIDL calls absent in GSI SystemUI."
                }
            )
        }

        // Tier 3: SystemUI UdfpsController / HBM / Sysfs / SurfaceFlinger sync
        val liveOrDumpsysDiffs = diffs.filter {
            it.category == "LIVE EXECUTION & SYSFS" ||
                it.category == "DUMPSYS SERVICES" ||
                it.category == "DISPLAY / HBM PIPELINE" ||
                it.category == "LIVE LOGCAT CALLBACKS"
        }
        if (liveOrDumpsysDiffs.isNotEmpty()) {
            val hasStallOrSysfsDiff = liveOrDumpsysDiffs.any {
                it.title.contains("Sysfs", true) ||
                    it.title.contains("SILENT", true) ||
                    it.title.contains("HAL", true) ||
                    it.title.contains("SurfaceFlinger", true) ||
                    it.title.contains("display", true)
            }
            val sysUiFiles = extractables.filter { it.category == "SYSTEMUI_FRAMEWORK" }
            solutions += PortingCandidateSolution(
                id = "port_tier3_sysui_udfps",
                tier = PortingTier.SYSTEMUI_UDFPS,
                rank = rank++,
                title = if (language == AppLanguage.FR) {
                    "Niveau 3 : Adaptation UdfpsController / UdfpsDisplayMode / HBM côté SystemUI GSI"
                } else {
                    "Tier 3: Adapt UdfpsController / UdfpsDisplayMode / HBM inside GSI SystemUI"
                },
                layer = "SystemUI (UdfpsController / FingerprintService HBM Bridge)",
                requiresFrameworkOrSystemUi = true,
                confidencePercent = if (hasStallOrSysfsDiff) 94 else 70,
                whyItApplies = if (language == AppLanguage.FR) {
                    "L'analyse live prouve que la lumière/UI s'allume sur GSI mais que la transition matérielle HBM/Touch ou le signal onFingerDown/extCmd diverge de la Custom ROM."
                } else {
                    "Live traces prove FOD UI illuminates on GSI yet HBM/Touch hardware state transition or onFingerDown/extCmd diverges from Custom ROM."
                },
                exactSourcesInZip = (sysUiFiles.map { "${it.romFilePath} -> ${it.importantElements.take(4)}" } + liveOrDumpsysDiffs.take(8).map { "${it.sourceFile} -> ${it.title}" }).distinct().take(10),
                concreteActionSteps = listOf(
                    if (language == AppLanguage.FR) "Implémenter ou corriger le hook UdfpsHandler/PhhFod pour déclencher exactement le même état sysfs/DRM (disp_param/fod_status) observé sur Custom ROM."
                    else "Hook UdfpsHandler/PhhFod in GSI SystemUI to toggle the exact sysfs/DRM state (disp_param/fod_status) observed on Custom ROM.",
                    if (language == AppLanguage.FR) "Synchroniser SurfaceFlinger (calque UDFPS + dim layer + HBM) avant l'envoi de onFingerDown au HAL vendor inchangé."
                    else "Synchronize SurfaceFlinger (UDFPS layer + dim layer + HBM) before dispatching onFingerDown to untouched vendor HAL."
                ),
                limitations = if (language == AppLanguage.FR) {
                    "Nécessite un patch/module côté SystemUI GSI ou overlay Treble PhhFod ; boot et vendor restent inchangés."
                } else {
                    "Requires GSI SystemUI / PhhFod handler patch; boot and vendor remain untouched."
                }
            )
        }

        // Tier 4: Framework / BiometricService / Vendor HAL Extension Interface
        val halOrElfDiffs = diffs.filter { it.category == "HAL / VINTF / BINDER" || it.category == "ELF BINARIES & SYMBOLS" }
        if (halOrElfDiffs.isNotEmpty() || gsiZip.report?.summary?.enrollmentSucceeded == false) {
            solutions += PortingCandidateSolution(
                id = "port_tier4_framework_hal_ext",
                tier = PortingTier.FRAMEWORK_BIOMETRIC,
                rank = rank,
                title = if (language == AppLanguage.FR) {
                    "Niveau 4 : Passerelle Framework BiometricService / Extension HAL Vendor (AIDL/HIDL)"
                } else {
                    "Tier 4: Framework BiometricService / Vendor HAL Extension Bridge (AIDL/HIDL)"
                },
                layer = "Framework services.jar / Vendor Extension Binder Client (côté GSI)",
                requiresFrameworkOrSystemUi = true,
                confidencePercent = if (halOrElfDiffs.isNotEmpty()) 90 else 65,
                whyItApplies = if (language == AppLanguage.FR) {
                    "Le même binaire HAL vendor est utilisé sur les deux systèmes ; si la GSI n'appelle pas son extension propriétaire (extCmd / IXiaomiFingerprint / IOplusBiometricsFingerprint / sensorProps), le HAL reste silencieux au poser du doigt."
                } else {
                    "Identical vendor HAL binary runs on both systems; if GSI fails to invoke its vendor extension (extCmd / IXiaomiFingerprint / sensorProps), HAL stays silent on finger press."
                },
                exactSourcesInZip = (halOrElfDiffs + diffs.filter { it.sourceFile.contains("dumpsys_fingerprint") }).take(8).map { "${it.sourceFile} -> ${it.title}" },
                concreteActionSteps = listOf(
                    if (language == AppLanguage.FR) "Vérifier dans raw/lshal.txt et disassembly/elf_disassembly_full.txt les interfaces vendor appelées par le Framework Custom ROM."
                    else "Verify vendor Binder interfaces in raw/lshal.txt and disassembly/elf_disassembly_full.txt called by Custom ROM Framework.",
                    if (language == AppLanguage.FR) "Ajouter le pont client côté GSI (services/SystemUI/Treble app) vers l'interface HAL vendor existante sans toucher à /vendor."
                    else "Add GSI-side Binder client bridge (services/SystemUI/Treble app) calling existing vendor HAL without editing /vendor."
                ),
                limitations = if (language == AppLanguage.FR) {
                    "Solution la plus invasive côté GSI (Framework/SystemUI), à appliquer uniquement si les niveaux 1 à 3 ne déclenchent pas onAcquired."
                } else {
                    "Deepest GSI-side change (Framework/SystemUI), use only if Tiers 1–3 fail to trigger onAcquired."
                }
            )
        }

        return solutions.sortedBy { it.rank }
    }

    private fun buildFactualVerdict(
        romZip: RawZipArchiveBundle,
        gsiZip: RawZipArchiveBundle,
        diffs: List<PortFileDiffItem>,
        solutions: List<PortingCandidateSolution>,
        extractables: List<ExtractableFileItem>,
        language: AppLanguage
    ): String {
        val blockingCount = diffs.count { it.status == EvidenceStatus.FAILED }
        val topSol = solutions.maxByOrNull { it.confidencePercent } ?: solutions.firstOrNull()
        val liveBreaks = diffs.filter { it.category == "LIVE EXECUTION & SYSFS" || it.category == "LIVE LOGCAT CALLBACKS" }
        val topExtract = extractables.firstOrNull()
        return if (language == AppLanguage.FR) {
            buildString {
                appendLine("Archives analysées intégralement : ${romZip.totalFiles} fichiers ROM (${romZip.totalBytes / 1024} Ko) vs ${gsiZip.totalFiles} fichiers GSI (${gsiZip.totalBytes / 1024} Ko).")
                appendLine("$blockingCount divergence(s) critique(s) [FAILED] identifiée(s) sur des éléments qui fonctionnent sur la Custom ROM.")
                appendLine("${extractables.size} fichier(s)/mécanisme(s) concret(s) identifié(s) pour extraction depuis la Custom ROM.")
                if (topExtract != null) {
                    appendLine("Fichier prioritaire à extraire (${topExtract.priorityPercent}%) : ${topExtract.romFilePath} (Rép: ${topExtract.romDirectory} -> GSI: ${topExtract.targetGsiPath}).")
                }
                if (liveBreaks.isNotEmpty()) {
                    appendLine("Point de blocage live prouvé : ${liveBreaks.first().title} (${liveBreaks.first().sourceFile}).")
                }
                if (topSol != null) {
                    appendLine("Meilleure solution de portage déduite (${topSol.confidencePercent}% confiance) : ${topSol.title}.")
                }
            }.trim()
        } else {
            buildString {
                appendLine("Full archives inspected: ${romZip.totalFiles} ROM files (${romZip.totalBytes / 1024} KB) vs ${gsiZip.totalFiles} GSI files (${gsiZip.totalBytes / 1024} KB).")
                appendLine("$blockingCount critical [FAILED] divergence(s) found on mechanisms working in Custom ROM.")
                appendLine("${extractables.size} actionable file(s)/mechanism(s) identified for Custom ROM extraction.")
                if (topExtract != null) {
                    appendLine("Top file to extract (${topExtract.priorityPercent}%): ${topExtract.romFilePath} (Dir: ${topExtract.romDirectory} -> GSI: ${topExtract.targetGsiPath}).")
                }
                if (liveBreaks.isNotEmpty()) {
                    appendLine("Proven live block: ${liveBreaks.first().title} (${liveBreaks.first().sourceFile}).")
                }
                if (topSol != null) {
                    appendLine("Recommended porting path (${topSol.confidencePercent}% confidence): ${topSol.title}.")
                }
            }.trim()
        }
    }

    private fun loadOverlayInspections(zip: RawZipArchiveBundle): Map<String, OverlayDeepInspection> {
        val out = LinkedHashMap<String, OverlayDeepInspection>()
        zip.report?.overlayInspections?.forEach { out[it.packageName] = it }
        val raw = readRaw(zip, "raw/overlay_deep_inspect.txt")
        if (raw.isNotBlank()) {
            parseOverlayInspectText(raw).forEach { ov ->
                if (!out.containsKey(ov.packageName) || out[ov.packageName]?.apkPath == "UNKNOWN") {
                    out[ov.packageName] = ov
                }
            }
        }
        return out
    }

    internal fun parseFilteredNonFodCount(raw: String): Int {
        if (raw.isBlank()) return 0
        Regex("FILTERED_NON_FOD_COUNT=(\\d+)").find(raw)?.groupValues?.get(1)?.toIntOrNull()?.let { return it }
        return Regex("(\\d+)\\s+generic UI filtered").find(raw)?.groupValues?.get(1)?.toIntOrNull() ?: 0
    }

    internal fun parseOverlayInspectText(raw: String): List<OverlayDeepInspection> {
        if (raw.isBlank()) return emptyList()
        val list = mutableListOf<OverlayDeepInspection>()
        var pkg = ""
        var enabled = false
        var isStatic = false
        var priority = 0
        var target = ""
        var apkPath = "UNKNOWN"
        var dir = "UNKNOWN"
        var parsedScore: Int? = null
        var parsedStrict: Boolean? = null
        var liveMapped = false
        val manifest = mutableListOf<String>()
        val configs = mutableListOf<String>()
        val lookupWinners = mutableListOf<String>()
        val decodedArsc = mutableListOf<String>()
        val bytecodeMatched = mutableListOf<String>()
        val xmlLines = mutableListOf<String>()
        var inPseudoXml = false

        fun flush() {
            if (pkg.isBlank()) return
            val prelim = OverlayDeepInspection(
                packageName = pkg,
                targetPackage = target,
                apkPath = apkPath,
                directory = dir,
                isEnabled = enabled,
                isStatic = isStatic,
                priority = priority,
                manifestSummary = manifest.toList(),
                fodConfigEntries = configs.toList(),
                provenInLiveMaps = liveMapped,
                lookupWinners = lookupWinners.toList(),
                pseudoXmlSource = xmlLines.joinToString("\n"),
                decodedArscEntries = decodedArsc.toList(),
                bytecodeMatchedResourceKeys = bytecodeMatched.toList()
            )
            val finalScore = parsedScore ?: DynamicProvenanceInspector.computeFodOverlayScore(prelim)
            val finalStrict = parsedStrict ?: (
                bytecodeMatched.isNotEmpty() ||
                    lookupWinners.isNotEmpty() ||
                    configs.isNotEmpty() ||
                    decodedArsc.any { fodArscSignalRegex.containsMatchIn(it) } ||
                    finalScore >= 40
                )
            list += prelim.copy(fodRelevanceScore = finalScore, isStrictProvenFod = finalStrict)
        }

        for (line in raw.lineSequence()) {
            val t = line.trim()
            if (t == "PSEUDO_XML_START") {
                inPseudoXml = true
                continue
            } else if (t == "PSEUDO_XML_END") {
                inPseudoXml = false
                continue
            }
            if (inPseudoXml && t.startsWith("XML:")) {
                xmlLines += line.substringAfter("XML:")
                continue
            }
            if (t.startsWith("OVERLAY:")) {
                flush()
                pkg = t.removePrefix("OVERLAY:").trim()
                enabled = false; isStatic = false; priority = 0; target = ""
                apkPath = "UNKNOWN"; dir = "UNKNOWN"
                parsedScore = null; parsedStrict = null; liveMapped = false; inPseudoXml = false
                manifest.clear(); configs.clear(); lookupWinners.clear(); decodedArsc.clear()
                bytecodeMatched.clear(); xmlLines.clear()
            } else if (t.startsWith("ENABLED=")) {
                enabled = t.contains("ENABLED=true", true)
                isStatic = t.contains("STATIC=true", true)
                priority = Regex("PRIORITY=(\\d+)").find(t)?.groupValues?.get(1)?.toIntOrNull() ?: 0
                target = Regex("TARGET=([^|\\s]*)").find(t)?.groupValues?.get(1).orEmpty()
                parsedScore = Regex("SCORE=(\\d+)").find(t)?.groupValues?.get(1)?.toIntOrNull()
                liveMapped = t.contains("LIVE_MAPPED=true", true)
                if (t.contains("STRICT_PROVEN=", true)) {
                    parsedStrict = t.contains("STRICT_PROVEN=true", true)
                }
            } else if (t.startsWith("APK_PATH=")) {
                apkPath = t.removePrefix("APK_PATH=").trim()
            } else if (t.startsWith("DIRECTORY=")) {
                dir = t.removePrefix("DIRECTORY=").trim()
            } else if (t.startsWith("BYTECODE_MATCH:")) {
                bytecodeMatched += t.removePrefix("BYTECODE_MATCH:").trim()
            } else if (t.startsWith("LOOKUP_WINNER:")) {
                lookupWinners += t.removePrefix("LOOKUP_WINNER:").trim()
            } else if (t.startsWith("ARSC_ENTRY:")) {
                decodedArsc += t.removePrefix("ARSC_ENTRY:").trim()
            } else if (t.startsWith("MANIFEST:")) {
                manifest += t.removePrefix("MANIFEST:").trim()
            } else if (t.startsWith("CONTENT:")) {
                configs += t.removePrefix("CONTENT:").trim()
            }
        }
        flush()
        return list
    }

    private fun loadDexSourceExtracts(zip: RawZipArchiveBundle): List<DexSourceExtract> {
        val fromReport = zip.report?.dexSourceExtracts.orEmpty()
        if (fromReport.isNotEmpty()) return fromReport
        val raw = readRaw(zip, "raw/dex_source_extract.txt")
        if (raw.isBlank()) return emptyList()
        val out = mutableListOf<DexSourceExtract>()
        var archivePath = ""
        var targetHint = ""
        var containerType = "APK/JAR"
        val classes = mutableListOf<String>()
        val methods = mutableListOf<String>()
        val strings = mutableListOf<String>()
        val resolvedKeys = mutableListOf<String>()
        val traces = mutableListOf<DexMethodTrace>()
        var curTraceMethod = ""
        val curTraceRes = mutableListOf<String>()
        val curTraceCalls = mutableListOf<String>()
        val curTraceStrs = mutableListOf<String>()
        val outline = mutableListOf<String>()
        var inOutline = false

        fun flushTrace() {
            if (curTraceMethod.isBlank()) return
            traces += DexMethodTrace(
                fqMethod = curTraceMethod,
                invokedMethods = curTraceCalls.toList(),
                resolvedResKeys = curTraceRes.toList(),
                referencedStrings = curTraceStrs.toList()
            )
            curTraceMethod = ""
            curTraceRes.clear(); curTraceCalls.clear(); curTraceStrs.clear()
        }

        fun flush() {
            flushTrace()
            if (archivePath.isBlank()) return
            out += DexSourceExtract(
                archivePath = archivePath,
                targetHint = targetHint,
                matchedClasses = classes.toList(),
                matchedMethods = methods.toList(),
                matchedStrings = strings.toList(),
                sourcePseudoSummary = outline.joinToString("\n"),
                containerType = containerType,
                methodTraces = traces.toList(),
                resolvedResourceKeys = resolvedKeys.toList()
            )
        }

        for (line in raw.lineSequence()) {
            val t = line.trim()
            when {
                t == "SOURCE_OUTLINE_START" -> inOutline = true
                t == "SOURCE_OUTLINE_END" -> inOutline = false
                inOutline && t.startsWith("CODE:") -> outline += t.removePrefix("CODE:").trimStart()
                t.startsWith("DEX_ARCHIVE:") -> {
                    flush()
                    val body = t.removePrefix("DEX_ARCHIVE:").trim()
                    archivePath = body.substringBefore(" (").trim()
                    targetHint = body.substringAfter("(", "").substringBefore(")").trim()
                    containerType = if (body.contains("[") && body.contains("]")) {
                        body.substringAfterLast("[").substringBefore("]").trim().ifBlank { "APK/JAR" }
                    } else "APK/JAR"
                    classes.clear(); methods.clear(); strings.clear()
                    resolvedKeys.clear(); traces.clear(); outline.clear(); inOutline = false
                }
                t.startsWith("RES_KEY:") -> resolvedKeys += t.removePrefix("RES_KEY:").trim()
                t.startsWith("TRACE_METHOD:") -> {
                    flushTrace()
                    curTraceMethod = t.removePrefix("TRACE_METHOD:").trim()
                }
                t.startsWith("TRACE_RES:") -> curTraceRes += t.removePrefix("TRACE_RES:").trim()
                t.startsWith("TRACE_CALL:") -> curTraceCalls += t.removePrefix("TRACE_CALL:").trim()
                t.startsWith("TRACE_STR:") -> curTraceStrs += t.removePrefix("TRACE_STR:").trim()
                t.startsWith("CLASS:") -> classes += t.removePrefix("CLASS:").trim()
                t.startsWith("METHOD:") -> methods += t.removePrefix("METHOD:").trim()
                t.startsWith("STRING:") -> strings += t.removePrefix("STRING:").trim()
            }
        }
        flush()
        return out
    }

    private fun resolveZipCausalChain(
        zip: RawZipArchiveBundle,
        parsedOverlays: List<OverlayDeepInspection>,
        language: AppLanguage
    ): List<CausalChainLink> {
        val rep = zip.report
        if (rep != null && rep.causalChain.isNotEmpty()) return rep.causalChain

        val dexExtracts = loadDexSourceExtracts(zip)
        val binderRaw = readRaw(zip, "raw/binder_trace_delta.txt")
        val binderTraces = rep?.binderTraces?.takeIf { it.isNotEmpty() }
            ?: SystemProbeCollector.parseBinderTraceText(binderRaw)
        val sfDelta = readRaw(zip, "raw/surfaceflinger_live_delta.txt")
        val dmesgDelta = readRaw(zip, "raw/dmesg_delta.txt")
        val silentStall = rep?.sessionFlow?.any { it.id == "evt_silent_hal_stall" } == true

        return PatchAndArchitectureAnalyzer.buildCausalChainFromModel(
            rootGranted = rep?.environment?.rootGranted ?: (binderRaw.isNotBlank() || dmesgDelta.isNotBlank()),
            overlayInspections = parsedOverlays,
            dexExtracts = dexExtracts,
            binderTraces = binderTraces,
            procLiveMaps = rep?.procLiveMaps.orEmpty(),
            elfAnalyses = rep?.elfAnalyses.orEmpty(),
            sysfsTransitions = rep?.sysfsTransitions.orEmpty(),
            fingerDownChain = rep?.fingerDownChain.orEmpty(),
            dumpsysFingerprint = readRaw(zip, "raw/dumpsys_fingerprint.txt"),
            dumpsysBiometric = readRaw(zip, "raw/dumpsys_biometric.txt"),
            dumpsysSurfaceFlinger = readRaw(zip, "raw/dumpsys_surfaceflinger.txt"),
            surfaceFlingerLiveDelta = sfDelta,
            dmesgDelta = dmesgDelta,
            lshalOutput = readRaw(zip, "raw/lshal.txt"),
            serviceList = readRaw(zip, "raw/service_list.txt"),
            silentHalStall = silentStall,
            language = language
        )
    }

    private fun computeCausalBreakSummary(
        romChain: List<CausalChainLink>,
        gsiChain: List<CausalChainLink>,
        language: AppLanguage
    ): String {
        if (romChain.isEmpty()) return ""
        val firstBreak = romChain.indices.firstNotNullOfOrNull { idx ->
            val r = romChain[idx]
            val g = gsiChain.getOrNull(idx)
            val rOk = r.status == EvidenceStatus.CONFIRMED || r.status == EvidenceStatus.OBSERVED
            val gBad = g == null || g.status == EvidenceStatus.FAILED || g.status == EvidenceStatus.SUSPECT ||
                (r.status == EvidenceStatus.CONFIRMED && g.status == EvidenceStatus.UNKNOWN)
            if (rOk && gBad) r to g else null
        }
        return if (firstBreak != null) {
            val (r, g) = firstBreak
            if (language == AppLanguage.FR) {
                "Rupture causale au niveau [${r.title}] : ROM=${r.status} (${r.sourceFile}) vs GSI=${g?.status ?: "UNKNOWN"} ${g?.breakExplanation?.takeIf { it.isNotBlank() }?.let { "→ $it" }.orEmpty()}"
            } else {
                "Causal break at [${r.title}]: ROM=${r.status} (${r.sourceFile}) vs GSI=${g?.status ?: "UNKNOWN"} ${g?.breakExplanation?.takeIf { it.isNotBlank() }?.let { "→ $it" }.orEmpty()}"
            }
        } else {
            if (language == AppLanguage.FR) {
                "Différentiel multi-couches capturé sans rupture unique isolée (vérifier logs DEX/Binder ci-dessous)."
            } else {
                "Multi-layer divergence captured (inspect DEX/Binder layers below)."
            }
        }
    }

    private fun loadFileProvenance(zip: RawZipArchiveBundle): List<FileProvenanceArtifact> {
        val list = zip.report?.fileProvenance.orEmpty().toMutableList()
        val raw = readRaw(zip, "raw/file_provenance_index.txt")
        if (raw.isNotBlank()) {
            val parsed = parseFileProvenanceText(raw)
            val existingKeys = list.map { "${it.category}::${it.filePath}" }.toHashSet()
            parsed.forEach { p ->
                if ("${p.category}::${p.filePath}" !in existingKeys) {
                    list += p
                }
            }
        }
        return list
    }

    internal fun parseFileProvenanceText(raw: String): List<FileProvenanceArtifact> {
        if (raw.isBlank()) return emptyList()
        val out = mutableListOf<FileProvenanceArtifact>()
        var cat = ""
        var path = ""
        var dir = ""
        var key = ""
        var note: String? = null
        val details = mutableListOf<String>()

        fun flush() {
            if (path.isBlank()) return
            out += FileProvenanceArtifact(
                id = "parsed_${out.size}_${path.hashCode()}",
                category = cat.ifBlank { "UNKNOWN" },
                filePath = path,
                directory = dir.ifBlank { path.substringBeforeLast('/', "UNKNOWN") },
                matchedSymbolOrKey = key,
                importantContents = details.toList(),
                accessNote = note
            )
        }

        for (line in raw.lineSequence()) {
            val t = line.trim()
            if (t.startsWith("FILE: [")) {
                flush()
                cat = t.substringAfter("FILE: [").substringBefore("]")
                path = t.substringAfter("]").trim()
                dir = ""; key = ""; note = null; details.clear()
            } else if (t.startsWith("DIRECTORY=")) {
                dir = t.removePrefix("DIRECTORY=").trim()
            } else if (t.startsWith("KEY=")) {
                key = t.removePrefix("KEY=").trim()
            } else if (t.startsWith("DETAIL:")) {
                details += t.removePrefix("DETAIL:").trim()
            } else if (t.startsWith("NOTE:")) {
                note = t.removePrefix("NOTE:").trim()
            }
        }
        flush()
        return out
    }

    private fun readRaw(zip: RawZipArchiveBundle, path: String): String =
        zip.rawFiles[path] ?: zip.rawFiles.entries.firstOrNull { it.key.endsWith(path) }?.value.orEmpty()

    private fun extractEnvField(zip: RawZipArchiveBundle, prefix: String): String {
        val env = readRaw(zip, "metadata/environment.txt")
        return env.lineSequence()
            .firstOrNull { it.startsWith("$prefix:", ignoreCase = true) }
            ?.substringAfter(":")
            ?.trim()
            ?: "UNKNOWN"
    }

    private fun parseProps(raw: String): Map<String, String> {
        val map = LinkedHashMap<String, String>()
        for (line in raw.lineSequence()) {
            val m = propLineRegex.matchEntire(line.trim()) ?: continue
            map[m.groupValues[1]] = m.groupValues[2]
        }
        return map
    }

    private fun parseOverlayStates(raw: String): Map<String, Boolean> {
        val map = LinkedHashMap<String, Boolean>()
        for (line in raw.lineSequence()) {
            val t = line.trim()
            if (t.startsWith("[x]", true) || t.startsWith("[ ]", true)) {
                val enabled = t.startsWith("[x]", true)
                val name = t.drop(3).trim()
                if (name.isNotBlank()) map[name] = enabled
            } else if (t.contains("STATE_ENABLED") || t.contains("STATE_DISABLED")) {
                val enabled = t.contains("STATE_ENABLED")
                val pkg = t.substringBefore(":").substringBefore(" ").trim()
                if (pkg.isNotBlank()) map[pkg] = enabled
            }
        }
        return map
    }

    private fun extractKeyLines(raw: String, regex: Regex): List<String> =
        raw.lineSequence()
            .map { it.trim() }
            .filter { it.isNotBlank() && regex.containsMatchIn(it) }
            .distinct()
            .take(160)
            .toList()

    private fun normalizeAvc(line: String): String {
        val perm = avcPermRegex.find(line)?.value.orEmpty()
        val tclass = avcTclassRegex.find(line)?.value.orEmpty()
        val scontext = avcScontextRegex.find(line)?.groupValues?.get(1).orEmpty()
        return "$scontext::$perm::$tclass"
    }
}
