package com.example.engine

import com.example.i18n.AppLanguage
import com.example.model.EvidenceStatus
import com.example.model.KnowledgeLevel
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

    private val propLineRegex = Regex("^\\[(.+?)]: \\[(.*)]$")

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

        // 1. Exhaustive getprop_all.txt diff across ALL FOD/Display/Biometric/Treble/Vendor/System props
        diffGetpropFiles(romZip, gsiZip, factualDiffs, sharedNoise, language)

        // 2. Exhaustive cmd overlay / dumpsys_overlay diff (distinguishing active vs inactive overlays!)
        diffOverlayFiles(romZip, gsiZip, factualDiffs, sharedNoise, language)

        // 3. dumpsys_fingerprint + dumpsys_biometric + dumpsys_display + dumpsys_surfaceflinger
        diffDumpsysBiometricAndDisplay(romZip, gsiZip, factualDiffs, language)

        // 4. lshal + vintf_manifests + service_list
        diffHalAndBinderLayer(romZip, gsiZip, factualDiffs, sharedNoise, language)

        // 5. init_rc_snippets + sysfs_fod_nodes + selinux_denials
        diffInitSysfsAndSelinux(romZip, gsiZip, factualDiffs, sharedNoise, language)

        // 6. Live enrollment behavior (fingerDownChain, sysfsTransitions, dmesgDelta, logcat_enrollment)
        diffLiveExecutionAndLogs(romZip, gsiZip, factualDiffs, sharedNoise, language)

        // 7. ELF binaries & disassembly diff
        diffElfDisassembly(romZip, gsiZip, factualDiffs, language)

        val sortedDiffs = factualDiffs
            .distinctBy { "${it.sourceFile}::${it.title}" }
            .sortedWith(compareBy<PortFileDiffItem> { if (it.status == EvidenceStatus.FAILED) 0 else if (it.status == EvidenceStatus.SUSPECT) 1 else 2 }.thenBy { it.category })

        val sortedNoise = sharedNoise.distinctBy { "${it.sourceFile}::${it.title}" }

        // Build ranked system/GSI porting solutions strictly respecting untouched boot & vendor
        val solutions = buildRankedPortingSolutions(
            romZip = romZip,
            gsiZip = gsiZip,
            diffs = sortedDiffs,
            language = language
        )

        val verdict = buildFactualVerdict(
            romZip = romZip,
            gsiZip = gsiZip,
            diffs = sortedDiffs,
            solutions = solutions,
            language = language
        )

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
            portingSolutions = solutions
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
                    // Ignore build/date/serial noise
                    if (key.contains("build.date") || key.contains("build.id") || key.contains("build.fingerprint") && !key.contains("vendor")) {
                        noise += PortFileDiffItem(
                            id = "prop_build_${key.hashCode()}",
                            sourceFile = "raw/getprop_all.txt",
                            category = "METADATA_NOISE",
                            title = key,
                            romEvidence = rv,
                            gsiEvidence = gv,
                            impact = "Build metadata difference",
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
        diffs: MutableList<PortFileDiffItem>,
        noise: MutableList<PortFileDiffItem>,
        language: AppLanguage
    ) {
        val romLines = parseOverlayStates(readRaw(romZip, "raw/dumpsys_overlay.txt"))
        val gsiLines = parseOverlayStates(readRaw(gsiZip, "raw/dumpsys_overlay.txt"))
        val allNames = (romLines.keys + gsiLines.keys).distinct()

        for (pkg in allNames) {
            val rEnabled = romLines[pkg]
            val gEnabled = gsiLines[pkg]
            val isBiometricOrDisplayOverlay = pkg.contains("fod", true) || pkg.contains("udfps", true) ||
                pkg.contains("fingerprint", true) || pkg.contains("biometric", true) ||
                pkg.contains("treble", true) || pkg.contains("systemui", true) ||
                pkg.contains("display", true) || pkg.contains("overlay", true)
            if (!isBiometricOrDisplayOverlay) continue

            when {
                rEnabled == true && (gEnabled == null || gEnabled == false) -> {
                    val isGenericUi = pkg.contains("ambientcue", true) || pkg.contains("navbar", true)
                    val targetList = if (isGenericUi) noise else diffs
                    targetList += PortFileDiffItem(
                        id = "rro_miss_${pkg.hashCode()}",
                        sourceFile = "raw/dumpsys_overlay.txt",
                        category = "RRO OVERLAYS",
                        title = pkg,
                        romEvidence = "[x] ENABLED",
                        gsiEvidence = if (gEnabled == null) "ABSENT" else "[ ] INACTIVE",
                        impact = if (language == AppLanguage.FR) {
                            "Overlay RRO actif sur Custom ROM mais absent/inactif sur GSI (configuration config_udfps / display / framework)."
                        } else {
                            "RRO overlay enabled on Custom ROM yet missing/inactive on GSI."
                        },
                        status = if (pkg.contains("fod", true) || pkg.contains("udfps", true) || pkg.contains("fingerprint", true) || pkg.contains("systemui", true)) EvidenceStatus.FAILED else EvidenceStatus.SUSPECT,
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
                        sourceFile = "raw/dumpsys_overlay.txt",
                        category = "RRO OVERLAYS",
                        title = pkg,
                        romEvidence = "Absent on ROM",
                        gsiEvidence = "[x] ENABLED",
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
        val pairs = listOf(
            "raw/dumpsys_fingerprint.txt" to Regex("(sensor|udfps|fod|type=|supports|strength|resetLockout|acquired|client|hal).*", RegexOption.IGNORE_CASE),
            "raw/dumpsys_biometric.txt" to Regex("(sensor|modality|authenticator|strength|udfps|fod).*", RegexOption.IGNORE_CASE),
            "raw/dumpsys_display.txt" to Regex("(hbm|lhbm|brightness|hdr|colorMode|refreshRate|udfps|fod|ActiveMode).*", RegexOption.IGNORE_CASE),
            "raw/dumpsys_surfaceflinger.txt" to Regex("(udfps|fod|fingerprint|hbm|lhbm|dim|color|hwc|composer).*", RegexOption.IGNORE_CASE)
        )

        pairs.forEach { (file, kw) ->
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
                        "Divergence d'état réel dans $file (paramètres capteur UDFPS, HBM ou SurfaceFlinger)."
                    } else {
                        "State divergence inside $file (UDFPS sensorProps, HBM, or SurfaceFlinger pipeline)."
                    },
                    status = if (onlyRom.isNotEmpty()) EvidenceStatus.FAILED else EvidenceStatus.SUSPECT,
                    knowledgeLevel = KnowledgeLevel.FACT
                )
            }
        }
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

    private fun buildRankedPortingSolutions(
        romZip: RawZipArchiveBundle,
        gsiZip: RawZipArchiveBundle,
        diffs: List<PortFileDiffItem>,
        language: AppLanguage
    ): List<PortingCandidateSolution> {
        val solutions = mutableListOf<PortingCandidateSolution>()
        var rank = 1

        // Tier 1: Props / PHH / Treble Settings (zero Framework/SystemUI/Vendor edits)
        val propDiffs = diffs.filter { it.category == "PROPERTIES (getprop)" }
        if (propDiffs.isNotEmpty()) {
            val missingPhhOrFod = propDiffs.filter { it.status == EvidenceStatus.FAILED }
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
                exactSourcesInZip = propDiffs.take(8).map { "raw/getprop_all.txt -> ${it.title}: ROM=${it.romEvidence} | GSI=${it.gsiEvidence}" },
                concreteActionSteps = propDiffs.filter { it.romEvidence.contains("=") }.take(6).map {
                    "Aligner côté /system_ext ou Magisk/resetprop : ${it.romEvidence}"
                }.ifEmpty {
                    listOf(
                        if (language == AppLanguage.FR) "Comparer chaque propriété divergente de raw/getprop_all.txt et aligner côté /product ou Treble Settings."
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

        // Tier 2: RRO Overlays + Init.rc + System SELinux (still zero Framework/SystemUI Java recompile!)
        val rroDiffs = diffs.filter { it.category == "RRO OVERLAYS" }
        val initDiffs = diffs.filter { it.category == "INIT.RC TRIGGERS" }
        val selinuxDiffs = diffs.filter { it.category == "SELINUX AVC (GSI-ONLY)" }
        if (rroDiffs.isNotEmpty() || initDiffs.isNotEmpty() || selinuxDiffs.isNotEmpty()) {
            val sources = (rroDiffs + initDiffs + selinuxDiffs).take(8).map { "${it.sourceFile} -> ${it.title}" }
            solutions += PortingCandidateSolution(
                id = "port_tier2_rro_selinux",
                tier = PortingTier.RRO_INIT_SELINUX_SYSTEM,
                rank = rank++,
                title = if (language == AppLanguage.FR) {
                    "Niveau 2 : Portage des overlays RRO actifs, triggers init système & contexte SELinux"
                } else {
                    "Tier 2: Port active RRO overlays, system init triggers & system SELinux rules"
                },
                layer = "RRO Overlay (/product/overlay) + system_ext/etc/init + sepolicy système",
                requiresFrameworkOrSystemUi = false,
                confidencePercent = if (rroDiffs.any { it.status == EvidenceStatus.FAILED } || selinuxDiffs.isNotEmpty()) 85 else 55,
                whyItApplies = if (language == AppLanguage.FR) {
                    "Les ZIP prouvent ${rroDiffs.size} écart(s) d'overlay RRO actif, ${initDiffs.size} écart(s) init.rc et ${selinuxDiffs.size} refus AVC propres à la GSI."
                } else {
                    "ZIPs prove ${rroDiffs.size} active RRO overlay diffs, ${initDiffs.size} init.rc diffs, and ${selinuxDiffs.size} GSI-only AVC denials."
                },
                exactSourcesInZip = sources,
                concreteActionSteps = listOfNotNull(
                    rroDiffs.firstOrNull()?.let {
                        if (language == AppLanguage.FR) "Porter l'overlay RRO actif sur ROM (${it.title}) dans /product/overlay/ côté GSI (coordonnées UDFPS, HBM, config_biometric_sensors)."
                        else "Port ROM-active RRO overlay (${it.title}) to GSI /product/overlay/ (UDFPS coords, HBM, config_biometric_sensors)."
                    },
                    selinuxDiffs.firstOrNull()?.let {
                        if (language == AppLanguage.FR) "Autoriser dans plat_sepolicy / system_ext les accès refusés uniquement sur GSI (raw/selinux_denials.txt)."
                        else "Allow GSI-only denied contexts in plat_sepolicy / system_ext (raw/selinux_denials.txt)."
                    },
                    initDiffs.firstOrNull()?.let {
                        if (language == AppLanguage.FR) "Reproduire côté /system/etc/init/ les permissions/démarrages manquants observés dans raw/init_rc_snippets.txt."
                        else "Mirror missing init triggers observed in raw/init_rc_snippets.txt under /system/etc/init/."
                    }
                ),
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
                exactSourcesInZip = liveOrDumpsysDiffs.take(8).map { "${it.sourceFile} -> ${it.title}" },
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

        // Tier 4: Framework / BiometricService / Vendor HAL Extension Interface (when lshal/vintf/ELF show vendor extensions)
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
        language: AppLanguage
    ): String {
        val blockingCount = diffs.count { it.status == EvidenceStatus.FAILED }
        val topSol = solutions.maxByOrNull { it.confidencePercent } ?: solutions.firstOrNull()
        val liveBreaks = diffs.filter { it.category == "LIVE EXECUTION & SYSFS" || it.category == "LIVE LOGCAT CALLBACKS" }
        return if (language == AppLanguage.FR) {
            buildString {
                appendLine("Archives analysées intégralement : ${romZip.totalFiles} fichiers ROM (${romZip.totalBytes / 1024} Ko) vs ${gsiZip.totalFiles} fichiers GSI (${gsiZip.totalBytes / 1024} Ko).")
                appendLine("$blockingCount divergence(s) critique(s) [FAILED] identifiée(s) sur des éléments qui fonctionnent sur la Custom ROM.")
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
                if (liveBreaks.isNotEmpty()) {
                    appendLine("Proven live block: ${liveBreaks.first().title} (${liveBreaks.first().sourceFile}).")
                }
                if (topSol != null) {
                    appendLine("Recommended porting path (${topSol.confidencePercent}% confidence): ${topSol.title}.")
                }
            }.trim()
        }
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
        val perm = Regex("\\{[^}]+}").find(line)?.value.orEmpty()
        val tclass = Regex("tclass=\\S+").find(line)?.value.orEmpty()
        val scontext = Regex("scontext=u:r:([^:]+):").find(line)?.groupValues?.get(1).orEmpty()
        return "$scontext::$perm::$tclass"
    }
}
