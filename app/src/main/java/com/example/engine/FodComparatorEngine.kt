package com.example.engine

import com.example.i18n.AppLanguage
import com.example.model.ComparisonEntry
import com.example.model.ComparisonResult
import com.example.model.ComponentCategory
import com.example.model.EvidenceStatus
import com.example.model.FodDiagnosticReport
import com.example.model.KnowledgeLevel
import com.example.model.RemediationOption
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object FodComparatorEngine {

    fun compare(
        rom: FodDiagnosticReport,
        gsi: FodDiagnosticReport,
        language: AppLanguage
    ): ComparisonResult {
        val bootMatch = rom.environment.bootSignature == gsi.environment.bootSignature ||
            rom.environment.bootSignature.startsWith("UNKNOWN") ||
            gsi.environment.bootSignature.startsWith("UNKNOWN")
        val vendorMatch = rom.environment.vendorFingerprint == gsi.environment.vendorFingerprint ||
            rom.environment.vendorFingerprint == "UNKNOWN" ||
            gsi.environment.vendorFingerprint == "UNKNOWN"

        val parityOk = bootMatch && vendorMatch
        val paritySummary = if (parityOk) {
            "boot=[${rom.environment.bootSignature}] | vendor=[${rom.environment.vendorFingerprint}]"
        } else {
            "ROM(boot=${rom.environment.bootSignature}, vendor=${rom.environment.vendorFingerprint}) vs GSI(boot=${gsi.environment.bootSignature}, vendor=${gsi.environment.vendorFingerprint})"
        }

        val romByName = rom.components.associateBy { it.name }
        val gsiByName = gsi.components.associateBy { it.name }

        val commonDiffs = mutableListOf<ComparisonEntry>()
        val missingInGsi = mutableListOf<ComparisonEntry>()
        val versionInterfaceDiffs = mutableListOf<ComparisonEntry>()
        val incompatibleLibs = mutableListOf<ComparisonEntry>()

        for ((name, rComp) in romByName) {
            val gComp = gsiByName[name]
            if (gComp == null) {
                missingInGsi += ComparisonEntry(
                    title = name,
                    romDetail = "${rComp.category} · ${rComp.interfaceType} · ${rComp.version} (${rComp.status})",
                    gsiDetail = if (language == AppLanguage.FR) "Absent sur la GSI" else "Missing on GSI",
                    impact = if (rComp.category == ComponentCategory.OVERLAY || rComp.category == ComponentCategory.PROPERTY || rComp.category == ComponentCategory.PATCH) {
                        if (language == AppLanguage.FR) "Configuration/Overlay système présent sur ROM mais absent côté GSI (vendor intact)." else "System config/overlay present on ROM but absent on GSI (vendor untouched)."
                    } else {
                        if (language == AppLanguage.FR) "Composant ou interaction observé sur ROM non retrouvé sur GSI." else "Component/interaction observed on ROM not found on GSI."
                    },
                    status = EvidenceStatus.FAILED,
                    knowledgeLevel = KnowledgeLevel.FACT
                )
            } else {
                val changed = rComp.status != gComp.status ||
                    rComp.version != gComp.version ||
                    rComp.interfaceType != gComp.interfaceType ||
                    rComp.metadata != gComp.metadata

                if (changed) {
                    val entry = ComparisonEntry(
                        title = name,
                        romDetail = "${rComp.status} · ${rComp.version} · ${rComp.interfaceType} · ${rComp.metadata}",
                        gsiDetail = "${gComp.status} · ${gComp.version} · ${gComp.interfaceType} · ${gComp.metadata}",
                        impact = if (gComp.status == EvidenceStatus.FAILED && rComp.status != EvidenceStatus.FAILED) {
                            if (language == AppLanguage.FR) "Régression démontrée sur GSI." else "Demonstrated regression on GSI."
                        } else {
                            if (language == AppLanguage.FR) "Divergence de version, statut ou métadonnées." else "Version, status, or metadata divergence."
                        },
                        status = if (gComp.status == EvidenceStatus.FAILED) EvidenceStatus.FAILED else EvidenceStatus.SUSPECT,
                        knowledgeLevel = KnowledgeLevel.FACT
                    )
                    commonDiffs += entry
                    if (rComp.version != gComp.version || rComp.interfaceType != gComp.interfaceType || rComp.dependencies != gComp.dependencies) {
                        versionInterfaceDiffs += entry
                    }
                    if (rComp.category == ComponentCategory.LIBRARY || rComp.category == ComponentCategory.SERVICE) {
                        incompatibleLibs += entry
                    }
                }
            }
        }

        // Compare ALL patches, props, and overlays exhaustively
        val configAndPatchDiffs = mutableListOf<ComparisonEntry>()
        val romPatches = rom.patches.associateBy { it.name }
        val gsiPatches = gsi.patches.associateBy { it.name }
        val allPatchNames = (romPatches.keys + gsiPatches.keys).distinct()
        for (pName in allPatchNames) {
            val rp = romPatches[pName]
            val gp = gsiPatches[pName]
            if (rp == null && gp != null) {
                configAndPatchDiffs += ComparisonEntry(
                    title = pName,
                    romDetail = if (language == AppLanguage.FR) "Non présent (inutile sur Custom ROM)" else "Not present (not needed on Custom ROM)",
                    gsiDetail = "${gp.scope}: ${gp.rawValue} | Effet: ${gp.realObservedEffect}",
                    impact = if (language == AppLanguage.FR) {
                        "Patch spécifique GSI présent ; vérifier s'il cible le bon nœud/HAL vendor sans bloquer."
                    } else {
                        "GSI-specific patch present; verify whether it targets the actual vendor node/HAL."
                    },
                    status = EvidenceStatus.OBSERVED,
                    knowledgeLevel = KnowledgeLevel.FACT
                )
            } else if (rp != null && gp == null) {
                configAndPatchDiffs += ComparisonEntry(
                    title = pName,
                    romDetail = "${rp.scope}: ${rp.rawValue}",
                    gsiDetail = if (language == AppLanguage.FR) "ABSENT sur GSI" else "MISSING on GSI",
                    impact = if (language == AppLanguage.FR) {
                        "Propriété, overlay ou règle init présente sur la ROM fonctionnelle mais absente sur GSI."
                    } else {
                        "Property, overlay, or init rule present on working ROM but missing on GSI."
                    },
                    status = EvidenceStatus.FAILED,
                    knowledgeLevel = KnowledgeLevel.FACT
                )
            } else if (rp != null && gp != null && (rp.rawValue != gp.rawValue || rp.status != gp.status)) {
                configAndPatchDiffs += ComparisonEntry(
                    title = pName,
                    romDetail = "${rp.rawValue} (${rp.status})",
                    gsiDetail = "${gp.rawValue} (${gp.status}) · ${gp.realObservedEffect}",
                    impact = if (language == AppLanguage.FR) "Valeur ou activation divergente." else "Divergent value or activation state.",
                    status = EvidenceStatus.SUSPECT,
                    knowledgeLevel = KnowledgeLevel.FACT
                )
            }
        }

        // Live Enrollment Interaction Diffs
        val romPhases = rom.sessionFlow.groupBy { it.phase }
        val gsiPhases = gsi.sessionFlow.groupBy { it.phase }
        val missingLiveInteractions = mutableListOf<ComparisonEntry>()

        for ((phase, rEvents) in romPhases) {
            val rConfirmed = rEvents.count { it.status == EvidenceStatus.CONFIRMED }
            val gEvents = gsiPhases[phase].orEmpty()
            val gConfirmed = gEvents.count { it.status == EvidenceStatus.CONFIRMED }
            val gFailed = gEvents.count { it.status == EvidenceStatus.FAILED }

            if (rConfirmed > gConfirmed || gFailed > 0) {
                missingLiveInteractions += ComparisonEntry(
                    title = "Phase $phase",
                    romDetail = "$rConfirmed confirmed / ${rEvents.size} events (e.g. ${rEvents.firstOrNull { it.status == EvidenceStatus.CONFIRMED }?.summary ?: rEvents.first().summary})",
                    gsiDetail = "$gConfirmed confirmed, $gFailed failed / ${gEvents.size} events",
                    impact = if (gEvents.isEmpty()) {
                        if (language == AppLanguage.FR) "Interaction complètement absente pendant l'enregistrement GSI." else "Interaction completely absent during GSI enrollment."
                    } else {
                        if (language == AppLanguage.FR) "Rupture ou chute d'événements confirmés sur GSI." else "Drop or failure in confirmed events on GSI."
                    },
                    status = EvidenceStatus.FAILED,
                    knowledgeLevel = KnowledgeLevel.CORRELATION
                )
            }
        }

        // Demonstrated breaks
        val demonstratedBreaks = mutableListOf<ComparisonEntry>()
        gsi.sessionFlow.filter { it.isBlockingFailure }.forEach { blk ->
            demonstratedBreaks += ComparisonEntry(
                title = "${blk.phase} · ${blk.component}",
                romDetail = rom.summary.overallOutcome,
                gsiDetail = blk.rawEvidence,
                impact = blk.summary,
                status = EvidenceStatus.FAILED,
                knowledgeLevel = KnowledgeLevel.FACT
            )
        }
        if (demonstratedBreaks.isEmpty()) {
            demonstratedBreaks += ComparisonEntry(
                title = if (language == AppLanguage.FR) "Synthèse des ruptures GSI" else "GSI Break Summary",
                romDetail = rom.summary.firstDemonstratedBreak,
                gsiDetail = gsi.summary.firstDemonstratedBreak,
                impact = gsi.summary.realSuccessDespiteNoiseNote,
                status = if (gsi.summary.enrollmentSucceeded == false) EvidenceStatus.FAILED else EvidenceStatus.OBSERVED,
                knowledgeLevel = KnowledgeLevel.DEDUCTION
            )
        }

        // System-side remediation options (NEVER vendor/boot edits; prioritize NO Framework/SystemUI edits)
        val remediations = buildSystemRemediations(
            missingInGsi = missingInGsi,
            configAndPatchDiffs = configAndPatchDiffs,
            missingInteractions = missingLiveInteractions,
            gsi = gsi,
            language = language
        )

        val nowIso = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).format(Date())
        return ComparisonResult(
            romSessionId = rom.sessionId,
            gsiSessionId = gsi.sessionId,
            createdAtIso = nowIso,
            bootVendorParityVerified = parityOk,
            bootVendorParitySummary = paritySummary,
            commonComponentDiffs = commonDiffs,
            missingInGsi = missingInGsi,
            versionAndInterfaceDiffs = versionInterfaceDiffs,
            incompatibleLibsAndServices = incompatibleLibs,
            configAndPatchDiffs = configAndPatchDiffs,
            missingLiveInteractions = missingLiveInteractions,
            demonstratedBreaks = demonstratedBreaks,
            remediationOptions = remediations
        )
    }

    private fun buildSystemRemediations(
        missingInGsi: List<ComparisonEntry>,
        configAndPatchDiffs: List<ComparisonEntry>,
        missingInteractions: List<ComparisonEntry>,
        gsi: FodDiagnosticReport,
        language: AppLanguage
    ): List<RemediationOption> {
        val list = mutableListOf<RemediationOption>()

        val missingPropsOrOverlays = configAndPatchDiffs.filter { it.status == EvidenceStatus.FAILED }
        if (missingPropsOrOverlays.isNotEmpty()) {
            list += RemediationOption(
                id = "rem_props_rro",
                title = if (language == AppLanguage.FR) {
                    "Aligner propriétés système et overlays RRO manquants (sans toucher Framework/SystemUI/Vendor)"
                } else {
                    "Align missing system properties & RRO overlays (no Framework/SystemUI/Vendor edits)"
                },
                layer = "System Properties / RRO Overlay",
                requiresFrameworkOrSystemUi = false,
                description = if (language == AppLanguage.FR) {
                    "Des propriétés système ou overlays RRO actifs sur la Custom ROM manquent ou diffèrent sur la GSI. Leur ajout côté configuration système/RRO respecte l'invariant boot/vendor."
                } else {
                    "System properties or RRO overlays active on the working ROM are missing/different on GSI. Aligning them via system props/RRO keeps boot and vendor untouched."
                },
                supportingEvidence = missingPropsOrOverlays.take(6).joinToString("\n") { "- ${it.title}: ROM=[${it.romDetail}] vs GSI=[${it.gsiDetail}]" },
                limitations = if (language == AppLanguage.FR) {
                    "Ne suffit pas si la GSI ne possède pas l'interface Binder/extension vendor attendue."
                } else {
                    "Insufficient alone if the GSI lacks the required Binder/vendor extension call path."
                },
                status = EvidenceStatus.CONFIRMED
            )
        }

        if (gsi.rawArtifacts.selinuxDenials.contains("avc: denied", true)) {
            list += RemediationOption(
                id = "rem_selinux_system",
                title = if (language == AppLanguage.FR) {
                    "Corriger les refus SELinux côté contexte système/GSI (boot & vendor inchangés)"
                } else {
                    "Resolve system/GSI-side SELinux denials (boot & vendor untouched)"
                },
                layer = "SELinux / System Policy",
                requiresFrameworkOrSystemUi = false,
                description = if (language == AppLanguage.FR) {
                    "Des refus AVC ont été observés dans les journaux lors de l'accès aux services ou nœuds HBM/FOD."
                } else {
                    "AVC denials were observed in logs when accessing FOD/HBM services or nodes."
                },
                supportingEvidence = gsi.rawArtifacts.selinuxDenials.lines()
                    .filter { it.contains("avc: denied", true) }
                    .take(5)
                    .joinToString("\n"),
                limitations = if (language == AppLanguage.FR) {
                    "Les règles vendor_sepolicy étant figées avec /vendor, seuls les domaines/attributs côté system_ext/product ou paramètres phh/Treble peuvent être ajustés."
                } else {
                    "Since vendor sepolicy is immutable with /vendor, only system/product/Treble context adjustments apply."
                },
                status = EvidenceStatus.OBSERVED
            )
        }

        if (missingInteractions.any { it.title.contains("DISPLAY_HBM") || it.title.contains("FOD_OVERLAY") } ||
            missingInGsi.isNotEmpty()
        ) {
            list += RemediationOption(
                id = "rem_sysui_udfps",
                title = if (language == AppLanguage.FR) {
                    "Ajustement ciblé SystemUI / UdfpsController / HBM (dernier recours)"
                } else {
                    "Targeted SystemUI / UdfpsController / HBM hook (fallback)"
                },
                layer = "System / SystemUI / Framework",
                requiresFrameworkOrSystemUi = true,
                description = if (language == AppLanguage.FR) {
                    "Si les propriétés Treble/RRO ne déclenchent pas le même appel Binder ou HBM que la Custom ROM vers le HAL vendor inchangé, l'écart provient de l'implémentation Udfps/Biometric côté GSI."
                } else {
                    "If Treble props/RROs do not trigger the same Binder or HBM sequence to the untouched vendor HAL, the gap lies in GSI Udfps/Biometric implementation."
                },
                supportingEvidence = (missingInteractions + missingInGsi).take(6)
                    .joinToString("\n") { "- ${it.title}: ${it.impact}" },
                limitations = if (language == AppLanguage.FR) {
                    "Nécessite une modification SystemUI ou Framework GSI ; à n'envisager qu'après validation des couches RRO/props."
                } else {
                    "Requires GSI SystemUI/Framework changes; consider only after ruling out RRO/prop fixes."
                },
                status = EvidenceStatus.SUSPECT
            )
        }

        return list
    }
}
