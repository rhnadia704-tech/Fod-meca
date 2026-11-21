package com.example.engine

import android.content.Context
import com.example.i18n.AppLanguage
import com.example.i18n.stringsFor
import com.example.model.ComparisonResult
import com.example.model.EvidenceStatus
import com.example.model.FodDiagnosticReport
import com.google.firebase.Firebase
import com.google.firebase.FirebaseApp
import com.google.firebase.ai.ai
import com.google.firebase.ai.type.GenerativeBackend
import com.google.firebase.ai.type.ThinkingLevel
import com.google.firebase.ai.type.generationConfig
import com.google.firebase.ai.type.thinkingConfig
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.withTimeout

class GeminiFodAiAnalyzer(private val context: Context) {

    // Mandatory: gemini-4-carbon with ThinkingLevel.HIGH and NO maxOutputTokens set
    private val model by lazy {
        val config = generationConfig {
            thinkingConfig = thinkingConfig {
                thinkingLevel = ThinkingLevel.HIGH
            }
        }
        Firebase.ai(backend = GenerativeBackend.googleAI()).generativeModel(
            modelName = "gemini-4-carbon",
            generationConfig = config
        )
    }

    private fun isFirebaseInitialized(): Boolean {
        return try {
            FirebaseApp.getApps(context).isNotEmpty() || FirebaseApp.initializeApp(context) != null
        } catch (_: Exception) {
            false
        }
    }

    fun synthesizeDiagnosticStream(
        report: FodDiagnosticReport,
        language: AppLanguage
    ): Flow<String> = flow {
        if (!isFirebaseInitialized()) {
            emit(buildLocalForensicDiagnosticSynthesis(report, language))
            return@flow
        }

        val prompt = buildDiagnosticPrompt(report, language)
        val accumulator = StringBuilder()
        try {
            withTimeout(60_000L) {
                model.generateContentStream(prompt).collect { chunk ->
                    val text = chunk.text.orEmpty()
                    if (text.isNotEmpty()) {
                        accumulator.append(text)
                        emit(accumulator.toString())
                    }
                }
            }
            if (accumulator.isEmpty()) {
                emit(buildLocalForensicDiagnosticSynthesis(report, language))
            }
        } catch (e: IllegalStateException) {
            // Standalone CI APK without google-services.json
            if (e.message?.contains("FirebaseApp", ignoreCase = true) == true) {
                emit(buildLocalForensicDiagnosticSynthesis(report, language))
            } else {
                throw e
            }
        }
    }

    fun synthesizeComparisonStream(
        comparison: ComparisonResult,
        rom: FodDiagnosticReport,
        gsi: FodDiagnosticReport,
        language: AppLanguage
    ): Flow<String> = flow {
        if (!isFirebaseInitialized()) {
            emit(buildLocalForensicComparisonSynthesis(comparison, rom, gsi, language))
            return@flow
        }

        val prompt = buildComparisonPrompt(comparison, rom, gsi, language)
        val accumulator = StringBuilder()
        try {
            withTimeout(60_000L) {
                model.generateContentStream(prompt).collect { chunk ->
                    val text = chunk.text.orEmpty()
                    if (text.isNotEmpty()) {
                        accumulator.append(text)
                        emit(accumulator.toString())
                    }
                }
            }
            if (accumulator.isEmpty()) {
                emit(buildLocalForensicComparisonSynthesis(comparison, rom, gsi, language))
            }
        } catch (e: IllegalStateException) {
            if (e.message?.contains("FirebaseApp", ignoreCase = true) == true) {
                emit(buildLocalForensicComparisonSynthesis(comparison, rom, gsi, language))
            } else {
                throw e
            }
        }
    }

    internal fun buildLocalForensicDiagnosticSynthesis(
        report: FodDiagnosticReport,
        language: AppLanguage
    ): String {
        val notice = stringsFor(language).aiLocalFallbackNotice
        val chainText = if (report.fingerDownChain.isEmpty()) {
            if (language == AppLanguage.FR) "Aucune chaîne capturée." else "No execution chain captured."
        } else {
            report.fingerDownChain.joinToString("\n") { step ->
                "  ${step.order}. [${step.status}] ${step.stage} — ${step.detail}"
            }
        }
        val sysfsChanged = report.sysfsTransitions.filter { it.changed }
        val sysfsStatic = report.sysfsTransitions.filter { !it.changed }
        val hals = report.components.filter { it.category.name == "HAL" }
        val blocking = report.sessionFlow.filter { it.isBlockingFailure }

        return buildString {
            appendLine(notice)
            appendLine()
            appendLine("### [FACT] ${report.mode} · ${report.summary.overallOutcome}")
            appendLine("- Device: ${report.environment.deviceModel} | Android ${report.environment.androidRelease} | SELinux=${report.environment.selinuxMode} | Root=${report.environment.rootGranted}")
            appendLine("- HAL(s): ${if (hals.isEmpty()) "UNKNOWN" else hals.joinToString(", ") { "${it.name} (${it.interfaceType}, ${it.status})" }}")
            appendLine("- ${if (language == AppLanguage.FR) "Première rupture démontrée" else "First demonstrated break"}: ${report.summary.firstDemonstratedBreak}")
            appendLine("- ${if (language == AppLanguage.FR) "Bruit vs Résultat réel" else "Noise vs Real Outcome"}: ${report.summary.realSuccessDespiteNoiseNote}")
            appendLine()
            appendLine("### [FACT] ${if (language == AppLanguage.FR) "Chaîne au poser du doigt (T0 → T_live → T1)" else "Finger-Down Chain (T0 → T_live → T1)"}")
            appendLine(chainText)
            appendLine()
            appendLine("### [FACT] ${if (language == AppLanguage.FR) "Transitions sysfs FOD/HBM/Touch" else "Sysfs FOD/HBM/Touch Transitions"}")
            if (sysfsChanged.isNotEmpty()) {
                sysfsChanged.forEach { t ->
                    appendLine("  - CHANGED `${t.nodePath}`: `${t.beforeValue}` -> ${t.liveValues} -> `${t.afterValue}`")
                }
            } else {
                appendLine(
                    if (language == AppLanguage.FR) {
                        "  - Aucune transition détectée sur les ${sysfsStatic.size} nœuds sysfs surveillés."
                    } else {
                        "  - Zero state transitions detected across ${sysfsStatic.size} monitored sysfs nodes."
                    }
                )
            }
            if (blocking.isNotEmpty()) {
                appendLine()
                appendLine("### [FACT] ${if (language == AppLanguage.FR) "Ruptures bloquantes" else "Blocking Breaks"}")
                blocking.take(8).forEach { b ->
                    appendLine("  - [${b.phase}] ${b.component}: ${b.summary}")
                }
            }
            if (report.patches.isNotEmpty()) {
                appendLine()
                appendLine("### [CORRELATION] ${if (language == AppLanguage.FR) "Patchs / Overlays / Props détectés" else "Detected Patches / Overlays / Props"} (${report.patches.size})")
                report.patches.take(15).forEach { p ->
                    appendLine("  - [${p.status}] ${p.name}=${p.rawValue} → ${p.realObservedEffect}")
                }
            }
        }
    }

    internal fun buildLocalForensicComparisonSynthesis(
        comparison: ComparisonResult,
        rom: FodDiagnosticReport,
        gsi: FodDiagnosticReport,
        language: AppLanguage
    ): String {
        val notice = stringsFor(language).aiLocalFallbackNotice
        return buildString {
            appendLine(notice)
            appendLine()
            appendLine("### [FACT] ROM (${rom.summary.overallOutcome}) vs GSI (${gsi.summary.overallOutcome})")
            appendLine("- Boot/Vendor Parity: ${comparison.bootVendorParityVerified} (${comparison.bootVendorParitySummary})")
            appendLine()
            appendLine("### [FACT] ${if (language == AppLanguage.FR) "Vrais bloqueurs différentiels GSI (${comparison.trueGsiBlockers.size})" else "True GSI Differential Blockers (${comparison.trueGsiBlockers.size})"}")
            if (comparison.trueGsiBlockers.isEmpty()) {
                appendLine(if (language == AppLanguage.FR) "- Aucun écart différentiel bloquant capturé (vérifiez l'activation Root et relancez T0→T1 pendant le toucher FOD)." else "- No differential blocker captured (verify Root access and rerun T0→T1 during FOD touch).")
            } else {
                comparison.trueGsiBlockers.take(18).forEach { b ->
                    appendLine("- **[${b.status}] ${b.title}**")
                    appendLine("  - ROM: ${b.romDetail}")
                    appendLine("  - GSI: ${b.gsiDetail}")
                    appendLine("  - Impact: ${b.impact}")
                }
            }
            appendLine()
            appendLine("### [DEDUCTION] ${if (language == AppLanguage.FR) "Bruit partagé filtré (absent/KO sur LES DEUX = non bloquant)" else "Filtered Shared Noise (Missing/KO on BOTH = Non-Blocking)"} (${comparison.sharedNonBlockingItems.size})")
            comparison.sharedNonBlockingItems.take(8).forEach { s ->
                appendLine("- ${s.title}: ${s.impact}")
            }
            appendLine()
            appendLine("### [DEDUCTION] ${if (language == AppLanguage.FR) "Pistes correctives système (boot & vendor intacts)" else "System-Level Remediation Paths (untouched boot & vendor)"}")
            comparison.remediationOptions.forEach { r ->
                appendLine("- **${r.title}** (Framework/SystemUI=${r.requiresFrameworkOrSystemUi}): ${r.description}")
            }
        }
    }

    private fun buildDiagnosticPrompt(
        report: FodDiagnosticReport,
        language: AppLanguage
    ): String {
        val langInstr = if (language == AppLanguage.FR) {
            "Réponds exclusivement en français technique précis."
        } else {
            "Respond exclusively in precise technical English."
        }

        val componentsDump = report.components.take(60).joinToString("\n") {
            "- [${it.status}/${it.knowledgeLevel}] ${it.category} :: ${it.name} | ver=${it.version} | iface=${it.interfaceType} | path=${it.path} | note=${it.accessNote ?: "ok"}"
        }
        val patchesDump = report.patches.take(80).joinToString("\n") {
            "- [${it.status}] ${it.scope} :: ${it.name}=${it.rawValue} | effect=${it.realObservedEffect}"
        }
        val flowDump = report.sessionFlow.take(120).joinToString("\n") {
            "- [${it.status}] ${it.phase} (${it.component}) benign=${it.isBenignWarning} blocking=${it.isBlockingFailure} :: ${it.rawEvidence}"
        }
        val chainDump = report.fingerDownChain.joinToString("\n") {
            "- [${it.status}] Step ${it.order}: ${it.stage} -> ${it.detail} | ev=${it.evidence.take(140)}"
        }
        val sysfsDump = report.sysfsTransitions.joinToString("\n") {
            "- changed=${it.changed} | ${it.nodePath}: T0=${it.beforeValue} -> live=${it.liveValues} -> T1=${it.afterValue}"
        }
        val elfDump = report.elfAnalyses.take(12).joinToString("\n") {
            "- ${it.path} (${it.architecture}, readable=${it.isReadable}, err=${it.accessError}): needed=${it.dtNeeded.take(8)}, symbols=${it.fodSymbols.take(12)}, strings=${it.fodStrings.take(12)}\n${it.disassemblyPseudoCode.take(900)}"
        }

        return """
            $langInstr
            You are a senior Android AOSP Biometrics & Display FOD reverse-engineering analyst.
            CRITICAL RULES:
            1. NEVER invent events, HALs, libraries, or log lines not present in the evidence below.
            2. Anything marked UNKNOWN or blocked by access limitations MUST remain explicitly flagged as UNKNOWN/unverified.
            3. Strictly separate every statement into [FACT], [CORRELATION], [DEDUCTION], or [HYPOTHESIS].
            4. Analyze ALL detected patches without ignoring any.
            5. Explain clearly:
               - Real architecture discovered on this device (${report.mode})
               - Real finger-down execution chain: if FOD illumination turns on yet no onEnrollResult or onError arrives (silent HAL stall), identify the exact last confirmed step and first silent/broken step!
               - Real enrollment outcome vs non-blocking log warnings
               - Insights from sysfs transitions, kernel dmesg delta, and ELF disassembly if readable
               - Real effect of every detected patch/overlay/prop.

            ENVIRONMENT:
            Device: ${report.environment.deviceModel} | Android ${report.environment.androidRelease} (SDK ${report.environment.sdkInt})
            Mode: ${report.mode} | GSI suspected: ${report.environment.isGsiSuspected} (${report.environment.gsiIndicators})
            Boot: ${report.environment.bootSignature}
            Vendor: ${report.environment.vendorFingerprint}
            SELinux: ${report.environment.selinuxMode} | Root granted: ${report.environment.rootGranted}
            BiometricManager: ${report.environment.biometricHardwareStatus}
            Display: ${report.environment.displayModesSummary}
            Outcome: ${report.summary.overallOutcome} | Break: ${report.summary.firstDemonstratedBreak}
            Access Limitations: ${report.environment.accessLimitations.joinToString("; ")}

            FINGER-DOWN EXECUTION CHAIN:
            $chainDump

            SYSFS TRANSITIONS (T0 -> T_live -> T1):
            $sysfsDump

            DMESG KERNEL DELTA:
            ${report.rawArtifacts.dmesgDelta.take(2500)}

            SURFACEFLINGER LIVE DELTA:
            ${report.rawArtifacts.surfaceFlingerLiveDelta.take(1000)}

            COMPONENTS (${report.components.size}):
            $componentsDump

            PATCHES / PROPS / OVERLAYS (${report.patches.size}):
            $patchesDump

            LIVE ENROLLMENT SESSION FLOW (${report.sessionFlow.size}):
            $flowDump

            ELF & DISASSEMBLY (${report.elfAnalyses.size}):
            $elfDump

            SELINUX / AVC SNIPPETS:
            ${report.rawArtifacts.selinuxDenials.take(2500)}
        """.trimIndent()
    }

    private fun buildComparisonPrompt(
        comparison: ComparisonResult,
        rom: FodDiagnosticReport,
        gsi: FodDiagnosticReport,
        language: AppLanguage
    ): String {
        val langInstr = if (language == AppLanguage.FR) {
            "Réponds exclusivement en français technique structuré."
        } else {
            "Respond exclusively in structured technical English."
        }

        return """
            $langInstr
            You are performing an ultra-deep forensic comparison between a WORKING Custom ROM FOD capture and a FAILING GSI FOD capture.
            ARCHITECTURAL INVARIANT (MANDATORY):
            - Both Custom ROM and GSI run on the EXACT SAME UNTOUCHED boot and vendor partitions!
            - Do NOT propose modifying /vendor, vendor HAL binaries, or boot/kernel.
            - Focus 100% on TRUE DIFFERENTIAL GSI BLOCKERS (items that work/transition/exist on the working Custom ROM and fail/stall/stay silent on GSI).
            - EXCLUDE shared missing/failing baseline items (listed in SHARED NON-BLOCKING NOISE) from root-cause attribution because the Custom ROM works despite them!
            - Explain why the GSI FOD light turns on yet hangs silently without onEnrollResult or onError, despite all its detected patches.
            - Prioritize remediation strategies that do NOT require modifying Framework or SystemUI first, then list Framework/SystemUI gaps with proof and limits.
            - Strictly label [FACT], [CORRELATION], [DEDUCTION], or [HYPOTHESIS]. Never fabricate unseen logs.

            BOOT/VENDOR PARITY: ${comparison.bootVendorParityVerified} -> ${comparison.bootVendorParitySummary}

            ROM SUMMARY: ${rom.summary.overallOutcome} | ${rom.summary.realSuccessDespiteNoiseNote} | Break=${rom.summary.firstDemonstratedBreak}
            GSI SUMMARY: ${gsi.summary.overallOutcome} | ${gsi.summary.realSuccessDespiteNoiseNote} | Break=${gsi.summary.firstDemonstratedBreak}

            TRUE GSI DIFFERENTIAL BLOCKERS (${comparison.trueGsiBlockers.size}):
            ${comparison.trueGsiBlockers.take(40).joinToString("\n") { "- [${it.status}] ${it.title}: ROM=[${it.romDetail}] | GSI=[${it.gsiDetail}] -> ${it.impact}" }}

            SHARED NON-BLOCKING NOISE (MISSING/KO ON BOTH - IGNORE AS ROOT CAUSE, ${comparison.sharedNonBlockingItems.size}):
            ${comparison.sharedNonBlockingItems.take(25).joinToString("\n") { "- ${it.title}: ${it.impact}" }}

            ALL PATCH / CONFIG / OVERLAY DIFFS (${comparison.configAndPatchDiffs.size}):
            ${comparison.configAndPatchDiffs.take(60).joinToString("\n") { "- ${it.title}: ROM=[${it.romDetail}] vs GSI=[${it.gsiDetail}] -> ${it.impact}" }}

            MISSING LIVE INTERACTIONS (${comparison.missingLiveInteractions.size}):
            ${comparison.missingLiveInteractions.take(25).joinToString("\n") { "- ${it.title}: ROM=${it.romDetail} | GSI=${it.gsiDetail}" }}

            DEMONSTRATED BREAKS (${comparison.demonstratedBreaks.size}):
            ${comparison.demonstratedBreaks.take(20).joinToString("\n") { "- ${it.title}: ${it.gsiDetail} (${it.impact})" }}
        """.trimIndent()
    }
}
