package com.example.engine

import com.example.i18n.AppLanguage
import com.example.model.ComparisonResult
import com.example.model.FodDiagnosticReport
import com.google.firebase.Firebase
import com.google.firebase.ai.ai
import com.google.firebase.ai.type.GenerativeBackend
import com.google.firebase.ai.type.ThinkingLevel
import com.google.firebase.ai.type.generationConfig
import com.google.firebase.ai.type.thinkingConfig
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.withTimeout

class GeminiFodAiAnalyzer {

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

    fun synthesizeDiagnosticStream(
        report: FodDiagnosticReport,
        language: AppLanguage
    ): Flow<String> = flow {
        val prompt = buildDiagnosticPrompt(report, language)
        val accumulator = StringBuilder()
        withTimeout(60_000L) {
            model.generateContentStream(prompt).collect { chunk ->
                val text = chunk.text.orEmpty()
                if (text.isNotEmpty()) {
                    accumulator.append(text)
                    emit(accumulator.toString())
                }
            }
        }
    }

    fun synthesizeComparisonStream(
        comparison: ComparisonResult,
        rom: FodDiagnosticReport,
        gsi: FodDiagnosticReport,
        language: AppLanguage
    ): Flow<String> = flow {
        val prompt = buildComparisonPrompt(comparison, rom, gsi, language)
        val accumulator = StringBuilder()
        withTimeout(60_000L) {
            model.generateContentStream(prompt).collect { chunk ->
                val text = chunk.text.orEmpty()
                if (text.isNotEmpty()) {
                    accumulator.append(text)
                    emit(accumulator.toString())
                }
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
               - Real enrollment outcome vs non-blocking log warnings (why it succeeds despite warnings OR exact first demonstrable break)
               - Insights from ELF binaries / disassembly if readable
               - Real effect of every detected patch/overlay/prop.

            ENVIRONMENT:
            Device: ${report.environment.deviceModel} | Android ${report.environment.androidRelease} (SDK ${report.environment.sdkInt})
            Mode: ${report.mode} | GSI suspected: ${report.environment.isGsiSuspected} (${report.environment.gsiIndicators})
            Boot: ${report.environment.bootSignature}
            Vendor: ${report.environment.vendorFingerprint}
            SELinux: ${report.environment.selinuxMode} | Root granted: ${report.environment.rootGranted}
            BiometricManager: ${report.environment.biometricHardwareStatus}
            Display: ${report.environment.displayModesSummary}
            Access Limitations: ${report.environment.accessLimitations.joinToString("; ")}

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
            - Focus 100% on why the exact same vendor HAL & boot succeed with the Custom ROM's system layer and fail with the GSI's system layer.
            - Explain why the GSI still fails DESPITE all its detected patches.
            - Prioritize remediation strategies that do NOT require modifying Framework or SystemUI first, then list Framework/SystemUI gaps with proof and limits.
            - Strictly label [FACT], [CORRELATION], [DEDUCTION], [HYPOTHESIS]. Never fabricate unseen logs.

            BOOT/VENDOR PARITY: ${comparison.bootVendorParityVerified} -> ${comparison.bootVendorParitySummary}

            ROM SUMMARY: ${rom.summary.overallOutcome} | ${rom.summary.realSuccessDespiteNoiseNote} | Break=${rom.summary.firstDemonstratedBreak}
            GSI SUMMARY: ${gsi.summary.overallOutcome} | ${gsi.summary.realSuccessDespiteNoiseNote} | Break=${gsi.summary.firstDemonstratedBreak}

            MISSING IN GSI (${comparison.missingInGsi.size}):
            ${comparison.missingInGsi.take(40).joinToString("\n") { "- ${it.title}: ROM=${it.romDetail}" }}

            COMMON / VERSION / INTERFACE DIFFS (${comparison.commonComponentDiffs.size}):
            ${comparison.commonComponentDiffs.take(40).joinToString("\n") { "- ${it.title}: ROM=[${it.romDetail}] vs GSI=[${it.gsiDetail}]" }}

            ALL PATCH / CONFIG / OVERLAY DIFFS (${comparison.configAndPatchDiffs.size}):
            ${comparison.configAndPatchDiffs.take(60).joinToString("\n") { "- ${it.title}: ROM=[${it.romDetail}] vs GSI=[${it.gsiDetail}] -> ${it.impact}" }}

            MISSING LIVE INTERACTIONS (${comparison.missingLiveInteractions.size}):
            ${comparison.missingLiveInteractions.take(25).joinToString("\n") { "- ${it.title}: ROM=${it.romDetail} | GSI=${it.gsiDetail}" }}

            DEMONSTRATED BREAKS (${comparison.demonstratedBreaks.size}):
            ${comparison.demonstratedBreaks.take(20).joinToString("\n") { "- ${it.title}: ${it.gsiDetail} (${it.impact})" }}
        """.trimIndent()
    }
}
