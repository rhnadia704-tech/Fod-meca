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

    private val normBrightnessRegex = Regex("Brightness=[0-9.E-]+", RegexOption.IGNORE_CASE)
    private val normSdrBrightnessRegex = Regex("SdrBrightness=[0-9.E-]+", RegexOption.IGNORE_CASE)
    private val normStablePhysicalRegex = Regex("address StablePhysical\\{[^}]+\\}", RegexOption.IGNORE_CASE)
    private val normManufactureDateRegex = Regex("ManufactureDate\\{[^}]+\\}", RegexOption.IGNORE_CASE)
    private val normFrameRateOverrideRegex = Regex("frameRateOverride[^,|]*", RegexOption.IGNORE_CASE)

    fun compare(
        rom: FodDiagnosticReport,
        gsi: FodDiagnosticReport,
        language: AppLanguage
    ): ComparisonResult {
        val bootMatch = areBootSignaturesCompatible(
            rom.environment.bootSignature,
            gsi.environment.bootSignature
        )
        val vendorMatch = rom.environment.vendorFingerprint == gsi.environment.vendorFingerprint ||
            rom.environment.vendorFingerprint == "UNKNOWN" ||
            gsi.environment.vendorFingerprint == "UNKNOWN"

        val parityOk = bootMatch && vendorMatch
        val paritySummary = if (parityOk) {
            "boot=[${rom.environment.bootSignature}] | vendor=[${rom.environment.vendorFingerprint}]"
        } else {
            "ROM(boot=${rom.environment.bootSignature}, vendor=${rom.environment.vendorFingerprint}) vs GSI(boot=${gsi.environment.bootSignature}, vendor=${gsi.environment.vendorFingerprint})"
        }

        val sharedNonBlockingItems = mutableListOf<ComparisonEntry>()
        val trueGsiBlockers = mutableListOf<ComparisonEntry>()

        // Collect normalized baseline warning/limitation signatures present in working ROM so GSI doesn't get blamed for shared baseline noise
        val romLimitationSignatures = rom.environment.accessLimitations
            .map { normalizeLimitation(it) }
            .toHashSet()
        val romWarningSignatures = rom.sessionFlow
            .filter { it.isBenignWarning || it.isBlockingFailure || it.rawEvidence.contains("avc: denied", true) }
            .map { eventSignature(it.component, it.summary) }
            .toHashSet()

        // 0. Access limitations shared by BOTH ROM & GSI -> non-blocking shared noise
        gsi.environment.accessLimitations.forEach { gLimit ->
            val norm = normalizeLimitation(gLimit)
            if (norm in romLimitationSignatures) {
                sharedNonBlockingItems += ComparisonEntry(
                    title = if (language == AppLanguage.FR) "Limite/sonde partagée: ${norm.take(70)}" else "Shared probe limitation: ${norm.take(70)}",
                    romDetail = gLimit,
                    gsiDetail = gLimit,
                    impact = if (language == AppLanguage.FR) {
                        "Également absent/inaccessible sur la Custom ROM fonctionnelle → prouvé NON BLOQUANT."
                    } else {
                        "Equally missing/inaccessible on working Custom ROM → proven NON-BLOCKING."
                    },
                    status = EvidenceStatus.OBSERVED,
                    knowledgeLevel = KnowledgeLevel.DEDUCTION
                )
            }
        }

        val romByName = rom.components.associateBy { it.name }
        val gsiByName = gsi.components.associateBy { it.name }

        val commonDiffs = mutableListOf<ComparisonEntry>()
        val missingInGsi = mutableListOf<ComparisonEntry>()
        val versionInterfaceDiffs = mutableListOf<ComparisonEntry>()
        val incompatibleLibs = mutableListOf<ComparisonEntry>()

        for ((name, rComp) in romByName) {
            val gComp = gsiByName[name]
            val rIsMissingOrUnknown = rComp.status == EvidenceStatus.UNKNOWN || rComp.status == EvidenceStatus.FAILED
            if (gComp == null) {
                if (rIsMissingOrUnknown) {
                    sharedNonBlockingItems += ComparisonEntry(
                        title = name,
                        romDetail = "${rComp.status} (${rComp.accessNote ?: rComp.path})",
                        gsiDetail = if (language == AppLanguage.FR) "Également absent sur GSI" else "Also absent on GSI",
                        impact = if (language == AppLanguage.FR) {
                            "Élément non observé sur la ROM fonctionnelle et sur la GSI → non bloquant."
                        } else {
                            "Missing/unknown on both working ROM and GSI → non-blocking."
                        },
                        status = EvidenceStatus.OBSERVED,
                        knowledgeLevel = KnowledgeLevel.DEDUCTION
                    )
                } else {
                    val entry = ComparisonEntry(
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
                    missingInGsi += entry
                    trueGsiBlockers += entry
                }
            } else {
                val bothFailedOrUnknown = (rComp.status == EvidenceStatus.UNKNOWN && gComp.status == EvidenceStatus.UNKNOWN) ||
                    (rComp.status == EvidenceStatus.FAILED && gComp.status == EvidenceStatus.FAILED)

                if (bothFailedOrUnknown) {
                    sharedNonBlockingItems += ComparisonEntry(
                        title = name,
                        romDetail = "${rComp.status} · ${rComp.accessNote ?: rComp.version}",
                        gsiDetail = "${gComp.status} · ${gComp.accessNote ?: gComp.version}",
                        impact = if (language == AppLanguage.FR) {
                            "Statut ${rComp.status} identique sur la Custom ROM fonctionnelle et sur la GSI → exclu des bloqueurs."
                        } else {
                            "Identical ${rComp.status} on both working Custom ROM and GSI → excluded from blockers."
                        },
                        status = EvidenceStatus.OBSERVED,
                        knowledgeLevel = KnowledgeLevel.DEDUCTION
                    )
                    continue
                }

                val rMetaNorm = normalizeMetadataForComparison(rComp.metadata)
                val gMetaNorm = normalizeMetadataForComparison(gComp.metadata)
                val changed = rComp.status != gComp.status ||
                    rComp.version != gComp.version ||
                    rComp.interfaceType != gComp.interfaceType ||
                    rMetaNorm != gMetaNorm

                if (changed) {
                    val isRealRegression = !rIsMissingOrUnknown && (gComp.status == EvidenceStatus.FAILED || gComp.status == EvidenceStatus.UNKNOWN)
                    val entry = ComparisonEntry(
                        title = name,
                        romDetail = "${rComp.status} · ${rComp.version} · ${rComp.interfaceType} · ${rComp.metadata}",
                        gsiDetail = "${gComp.status} · ${gComp.version} · ${gComp.interfaceType} · ${gComp.metadata}",
                        impact = if (isRealRegression) {
                            if (language == AppLanguage.FR) "Régression démontrée sur GSI (fonctionnel sur ROM)." else "Demonstrated regression on GSI (working on ROM)."
                        } else {
                            if (language == AppLanguage.FR) "Divergence de version, statut ou métadonnées." else "Version, status, or metadata divergence."
                        },
                        status = if (isRealRegression) EvidenceStatus.FAILED else EvidenceStatus.SUSPECT,
                        knowledgeLevel = KnowledgeLevel.FACT
                    )
                    commonDiffs += entry
                    if (isRealRegression) {
                        trueGsiBlockers += entry
                    }
                    if (rComp.version != gComp.version || rComp.interfaceType != gComp.interfaceType || rComp.dependencies != gComp.dependencies) {
                        versionInterfaceDiffs += entry
                    }
                    if (rComp.category == ComponentCategory.LIBRARY || rComp.category == ComponentCategory.SERVICE) {
                        incompatibleLibs += entry
                    }
                }
            }
        }

        // 1. Compare fingerDownChain stages (Pinpoints exact silent stall stage vs ROM)
        val romChain = rom.fingerDownChain.associateBy { it.order }
        val gsiChain = gsi.fingerDownChain.associateBy { it.order }
        for ((order, rStep) in romChain) {
            val gStep = gsiChain[order] ?: continue
            val rOk = rStep.status == EvidenceStatus.CONFIRMED || rStep.status == EvidenceStatus.OBSERVED
            val gBroken = gStep.status == EvidenceStatus.FAILED || gStep.status == EvidenceStatus.SUSPECT || gStep.status == EvidenceStatus.UNKNOWN
            if (rOk && gBroken) {
                trueGsiBlockers += ComparisonEntry(
                    title = if (language == AppLanguage.FR) "Rupture chaîne FOD : ${gStep.stage}" else "FOD Chain Break: ${gStep.stage}",
                    romDetail = "[${rStep.status}] ${rStep.detail}",
                    gsiDetail = "[${gStep.status}] ${gStep.detail}",
                    impact = if (language == AppLanguage.FR) {
                        "Cette étape fonctionne sur la Custom ROM mais bloque ou reste silencieuse sur la GSI."
                    } else {
                        "This stage succeeds on the Custom ROM yet fails or stays silent on GSI."
                    },
                    status = EvidenceStatus.FAILED,
                    knowledgeLevel = KnowledgeLevel.FACT
                )
            } else if (!rOk && gBroken && rStep.status == gStep.status) {
                sharedNonBlockingItems += ComparisonEntry(
                    title = gStep.stage,
                    romDetail = "[${rStep.status}] ${rStep.detail}",
                    gsiDetail = "[${gStep.status}] ${gStep.detail}",
                    impact = if (language == AppLanguage.FR) {
                        "Étape identiquement inaccessible/non observée sur les deux ROM."
                    } else {
                        "Stage identically unavailable/unobserved on both ROMs."
                    },
                    status = EvidenceStatus.OBSERVED,
                    knowledgeLevel = KnowledgeLevel.DEDUCTION
                )
            }
        }

        // 2. Compare sysfsTransitions (ROM node transitions during finger down vs stagnant on GSI)
        val romSysfs = rom.sysfsTransitions.associateBy { it.nodePath }
        val gsiSysfs = gsi.sysfsTransitions.associateBy { it.nodePath }
        val allSysfsPaths = (romSysfs.keys + gsiSysfs.keys).distinct()
        for (path in allSysfsPaths) {
            val rt = romSysfs[path]
            val gt = gsiSysfs[path]
            if (rt != null && rt.changed && (gt == null || !gt.changed)) {
                trueGsiBlockers += ComparisonEntry(
                    title = "Sysfs FOD/HBM inert : ${path.substringAfterLast('/')}",
                    romDetail = "Transition: ${rt.beforeValue} -> ${rt.liveValues} -> ${rt.afterValue}",
                    gsiDetail = if (gt == null) {
                        if (language == AppLanguage.FR) "Nœud non observé sur GSI" else "Node not observed on GSI"
                    } else {
                        if (language == AppLanguage.FR) "Inerte (aucune transition): ${gt.beforeValue} -> ${gt.afterValue}" else "Stagnant (no transition): ${gt.beforeValue} -> ${gt.afterValue}"
                    },
                    impact = if (language == AppLanguage.FR) {
                        "Sur la ROM fonctionnelle, ce nœud noyau bascule au poser du doigt ; sur la GSI, la lumière brille mais ce nœud matériel reste figé."
                    } else {
                        "On working ROM this kernel node transitions on finger touch; on GSI the light shines yet this hardware node stays unchanged."
                    },
                    status = EvidenceStatus.FAILED,
                    knowledgeLevel = KnowledgeLevel.FACT
                )
            } else if (rt != null && !rt.changed && gt != null && !gt.changed) {
                sharedNonBlockingItems += ComparisonEntry(
                    title = "Sysfs ${path.substringAfterLast('/')}",
                    romDetail = "Static: ${rt.beforeValue}",
                    gsiDetail = "Static: ${gt.beforeValue}",
                    impact = if (language == AppLanguage.FR) {
                        "Inchangé sur ROM comme sur GSI → non bloquant."
                    } else {
                        "Unchanged on both ROM and GSI → non-blocking."
                    },
                    status = EvidenceStatus.OBSERVED,
                    knowledgeLevel = KnowledgeLevel.FACT
                )
            }
        }

        // 3. Kernel dmesg delta comparison (only meaningful if both had root)
        val romDmesgActive = !rom.rawArtifacts.dmesgDelta.startsWith("DMESG_UNAVAILABLE") &&
            !rom.rawArtifacts.dmesgDelta.startsWith("NO_NEW_FOD") &&
            rom.rawArtifacts.dmesgDelta.isNotBlank()
        val gsiDmesgSilent = gsi.rawArtifacts.dmesgDelta.startsWith("NO_NEW_FOD")
        if (romDmesgActive && gsiDmesgSilent) {
            trueGsiBlockers += ComparisonEntry(
                title = if (language == AppLanguage.FR) "Absence d'événements kernel dmesg FOD/Touch sur GSI" else "Missing FOD/Touch kernel dmesg events on GSI",
                romDetail = rom.rawArtifacts.dmesgDelta.lines().take(3).joinToString(" | "),
                gsiDetail = gsi.rawArtifacts.dmesgDelta,
                impact = if (language == AppLanguage.FR) {
                    "Le même noyau reçoit des interruptions/appels FOD sur Custom ROM mais aucune commande n'atteint le pilote sous GSI."
                } else {
                    "Same kernel logs FOD driver activity on Custom ROM, yet zero commands reach the driver under GSI."
                },
                status = EvidenceStatus.FAILED,
                knowledgeLevel = KnowledgeLevel.FACT
            )
        }

        // 4. Compare ALL patches, props, and overlays exhaustively
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
                val entry = ComparisonEntry(
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
                configAndPatchDiffs += entry
                trueGsiBlockers += entry
            } else if (rp != null && gp != null && (rp.rawValue != gp.rawValue || rp.status != gp.status)) {
                val entry = ComparisonEntry(
                    title = pName,
                    romDetail = "${rp.rawValue} (${rp.status})",
                    gsiDetail = "${gp.rawValue} (${gp.status}) · ${gp.realObservedEffect}",
                    impact = if (language == AppLanguage.FR) "Valeur ou activation divergente." else "Divergent value or activation state.",
                    status = EvidenceStatus.SUSPECT,
                    knowledgeLevel = KnowledgeLevel.FACT
                )
                configAndPatchDiffs += entry
                if (rp.status == EvidenceStatus.CONFIRMED && gp.status != EvidenceStatus.CONFIRMED) {
                    trueGsiBlockers += entry
                }
            }
        }

        // 5. Live Enrollment Interaction Diffs (excluding shared benign noise)
        val romPhases = rom.sessionFlow.groupBy { it.phase }
        val gsiPhases = gsi.sessionFlow.groupBy { it.phase }
        val missingLiveInteractions = mutableListOf<ComparisonEntry>()

        for ((phase, rEvents) in romPhases) {
            val rConfirmed = rEvents.count { it.status == EvidenceStatus.CONFIRMED }
            val gEvents = gsiPhases[phase].orEmpty()
            val gConfirmed = gEvents.count { it.status == EvidenceStatus.CONFIRMED }
            val gFailedUnique = gEvents.count {
                it.status == EvidenceStatus.FAILED && eventSignature(it.component, it.summary) !in romWarningSignatures
            }

            if (rConfirmed > gConfirmed || gFailedUnique > 0) {
                val entry = ComparisonEntry(
                    title = "Phase $phase",
                    romDetail = "$rConfirmed confirmed / ${rEvents.size} events (e.g. ${rEvents.firstOrNull { it.status == EvidenceStatus.CONFIRMED }?.summary ?: rEvents.first().summary})",
                    gsiDetail = "$gConfirmed confirmed, $gFailedUnique failed / ${gEvents.size} events",
                    impact = if (gEvents.isEmpty()) {
                        if (language == AppLanguage.FR) "Interaction complètement absente pendant l'enregistrement GSI." else "Interaction completely absent during GSI enrollment."
                    } else {
                        if (language == AppLanguage.FR) "Rupture ou chute d'événements confirmés sur GSI." else "Drop or failure in confirmed events on GSI."
                    },
                    status = EvidenceStatus.FAILED,
                    knowledgeLevel = KnowledgeLevel.CORRELATION
                )
                missingLiveInteractions += entry
                trueGsiBlockers += entry
            }
        }

        // 6. Demonstrated breaks (only GSI-unique breaks; shared warnings go to sharedNonBlockingItems)
        val demonstratedBreaks = mutableListOf<ComparisonEntry>()
        gsi.sessionFlow.filter { it.isBlockingFailure || it.isBenignWarning }.forEach { evt ->
            val sig = eventSignature(evt.component, evt.summary)
            if (sig in romWarningSignatures) {
                sharedNonBlockingItems += ComparisonEntry(
                    title = "Log partagé : ${evt.phase} · ${evt.component}",
                    romDetail = "Présent aussi sur ROM fonctionnelle",
                    gsiDetail = evt.rawEvidence.take(180),
                    impact = if (language == AppLanguage.FR) {
                        "Avertissement/erreur également observé sur la Custom ROM qui fonctionne → non bloquant."
                    } else {
                        "Warning/error also present on working Custom ROM → proven non-blocking."
                    },
                    status = EvidenceStatus.OBSERVED,
                    knowledgeLevel = KnowledgeLevel.CORRELATION
                )
            } else if (evt.isBlockingFailure) {
                val entry = ComparisonEntry(
                    title = "${evt.phase} · ${evt.component}",
                    romDetail = rom.summary.overallOutcome,
                    gsiDetail = evt.rawEvidence,
                    impact = evt.summary,
                    status = EvidenceStatus.FAILED,
                    knowledgeLevel = KnowledgeLevel.FACT
                )
                demonstratedBreaks += entry
                trueGsiBlockers += entry
            }
        }
        if (demonstratedBreaks.isEmpty()) {
            val summaryBreak = ComparisonEntry(
                title = if (language == AppLanguage.FR) "Synthèse des ruptures GSI" else "GSI Break Summary",
                romDetail = "${rom.summary.overallOutcome} (${rom.summary.firstDemonstratedBreak})",
                gsiDetail = "${gsi.summary.overallOutcome} (${gsi.summary.firstDemonstratedBreak})",
                impact = gsi.summary.realSuccessDespiteNoiseNote,
                status = if (gsi.summary.enrollmentSucceeded == false) EvidenceStatus.FAILED else EvidenceStatus.OBSERVED,
                knowledgeLevel = KnowledgeLevel.DEDUCTION
            )
            demonstratedBreaks += summaryBreak
            if (gsi.summary.enrollmentSucceeded == false && trueGsiBlockers.none { it.title == summaryBreak.title }) {
                trueGsiBlockers += summaryBreak
            }
        }

        val sortedTrueBlockers = trueGsiBlockers
            .distinctBy { it.title }
            .sortedBy { if (it.status == EvidenceStatus.FAILED) 0 else 1 }

        val distinctSharedNoise = sharedNonBlockingItems.distinctBy { it.title }

        // 7. System-side remediation options (NEVER vendor/boot edits; prioritize NO Framework/SystemUI edits)
        val remediations = buildSystemRemediations(
            trueGsiBlockers = sortedTrueBlockers,
            configAndPatchDiffs = configAndPatchDiffs,
            missingInteractions = missingLiveInteractions,
            romWarningSignatures = romWarningSignatures,
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
            remediationOptions = remediations,
            trueGsiBlockers = sortedTrueBlockers,
            sharedNonBlockingItems = distinctSharedNoise
        )
    }

    private fun normalizeMetadataForComparison(meta: Map<String, String>): Map<String, String> =
        meta.mapValues { (_, v) ->
            v.replace(normBrightnessRegex, "Brightness=<norm>")
                .replace(normSdrBrightnessRegex, "SdrBrightness=<norm>")
                .replace(normStablePhysicalRegex, "address=<norm>")
                .replace(normManufactureDateRegex, "ManufactureDate=<norm>")
                .replace(normFrameRateOverrideRegex, "")
                .trim()
        }

    private fun normalizeLimitation(raw: String): String =
        raw.lowercase()
            .replace(Regex("exit=\\d+"), "")
            .replace(Regex("\\d+"), "#")
            .trim()

    private fun eventSignature(component: String, summary: String): String =
        "${component.lowercase().trim()}::${summary.lowercase().replace(Regex("\\d+"), "#").take(64).trim()}"

    private fun buildSystemRemediations(
        trueGsiBlockers: List<ComparisonEntry>,
        configAndPatchDiffs: List<ComparisonEntry>,
        missingInteractions: List<ComparisonEntry>,
        romWarningSignatures: Set<String>,
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

        val gsiUniqueDenials = gsi.rawArtifacts.selinuxDenials.lines()
            .filter { it.contains("avc: denied", true) }
            .filter { line ->
                val tag = line.substringAfter("scontext=", "").take(40)
                eventSignature("selinux", tag) !in romWarningSignatures
            }
            .distinct()

        if (gsiUniqueDenials.isNotEmpty()) {
            list += RemediationOption(
                id = "rem_selinux_system",
                title = if (language == AppLanguage.FR) {
                    "Corriger les refus SELinux spécifiques GSI côté contexte système (boot & vendor inchangés)"
                } else {
                    "Resolve GSI-unique system-side SELinux denials (boot & vendor untouched)"
                },
                layer = "SELinux / System Policy",
                requiresFrameworkOrSystemUi = false,
                description = if (language == AppLanguage.FR) {
                    "Des refus AVC absents de la Custom ROM fonctionnelle ont été observés côté GSI."
                } else {
                    "AVC denials absent on the working Custom ROM were observed on GSI."
                },
                supportingEvidence = gsiUniqueDenials.take(5).joinToString("\n"),
                limitations = if (language == AppLanguage.FR) {
                    "Les règles vendor_sepolicy étant figées avec /vendor, seuls les domaines/attributs côté system_ext/product ou paramètres Treble peuvent être ajustés."
                } else {
                    "Since vendor sepolicy is immutable with /vendor, only system/product/Treble context adjustments apply."
                },
                status = EvidenceStatus.OBSERVED
            )
        }

        val hbmOrSilentStallBlockers = trueGsiBlockers.filter {
            it.title.contains("Sysfs", true) ||
                it.title.contains("HBM", true) ||
                it.title.contains("HAL", true) ||
                it.title.contains("FOD", true)
        }
        if (hbmOrSilentStallBlockers.isNotEmpty() || missingInteractions.isNotEmpty()) {
            list += RemediationOption(
                id = "rem_sysui_udfps",
                title = if (language == AppLanguage.FR) {
                    "Corriger la passerelle Udfps / HBM / onFingerDown côté SystemUI ou Framework GSI (dernier recours)"
                } else {
                    "Fix Udfps / HBM / onFingerDown dispatch in GSI SystemUI or Framework (fallback)"
                },
                layer = "System / SystemUI / Framework",
                requiresFrameworkOrSystemUi = true,
                description = if (language == AppLanguage.FR) {
                    "La lumière FOD brille sur la GSI mais les nœuds HBM/Touch ou le callback onFingerDown/extCmd n'atteignent pas le HAL vendor comme sur la Custom ROM."
                } else {
                    "FOD illumination activates on GSI, yet HBM/Touch nodes or onFingerDown/extCmd do not reach the untouched vendor HAL like Custom ROM does."
                },
                supportingEvidence = hbmOrSilentStallBlockers.take(6)
                    .joinToString("\n") { "- ${it.title}: ROM=[${it.romDetail}] vs GSI=[${it.gsiDetail}]" },
                limitations = if (language == AppLanguage.FR) {
                    "Nécessite un correctif UdfpsController / FingerprintService côté GSI ; jamais côté vendor/boot."
                } else {
                    "Requires GSI UdfpsController / FingerprintService fix; never vendor/boot."
                },
                status = EvidenceStatus.FAILED
            )
        }

        return list
    }

    internal fun areBootSignaturesCompatible(romBoot: String, gsiBoot: String): Boolean {
        if (romBoot == gsiBoot || romBoot.startsWith("UNKNOWN") || gsiBoot.startsWith("UNKNOWN")) {
            return true
        }
        val rTokens = romBoot.split("|").map { it.trim() }.filter { it.isNotBlank() && !it.startsWith("UNKNOWN") }.toSet()
        val gTokens = gsiBoot.split("|").map { it.trim() }.filter { it.isNotBlank() && !it.startsWith("UNKNOWN") }.toSet()
        return rTokens.isNotEmpty() && gTokens.isNotEmpty() && rTokens.intersect(gTokens).isNotEmpty()
    }
}
