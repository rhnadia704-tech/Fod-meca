package com.example.storage

import android.content.Context
import android.net.Uri
import android.os.Environment
import com.example.i18n.AppLanguage
import com.example.model.ComparisonResult
import com.example.model.FodDiagnosticReport
import com.example.model.PortAnalysisResult
import com.example.model.RawZipArchiveBundle
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedOutputStream
import java.io.BufferedWriter
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.OutputStreamWriter
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

object StreamingReportExporter {

    private val moshi: Moshi = Moshi.Builder()
        .addLast(KotlinJsonAdapterFactory())
        .build()

    private val reportAdapter = moshi.adapter(FodDiagnosticReport::class.java).indent("  ")

    fun defaultDirectDirectory(): File {
        val dir = File(
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
            "FodDetector"
        )
        if (!dir.exists()) dir.mkdirs()
        return dir
    }

    suspend fun exportDiagnosticZip(
        context: Context,
        report: FodDiagnosticReport,
        language: AppLanguage,
        targetUri: Uri?,
        directFileName: String? = null
    ): String = withContext(Dispatchers.IO) {
        val (stream, label) = openTargetOutput(context, targetUri, directFileName ?: "fod_${report.mode.name.lowercase()}_${report.sessionId}.zip")
        stream.use { out ->
            ZipOutputStream(BufferedOutputStream(out, 64 * 1024)).use { zip ->
                writeZipEntry(zip, "report.json") { writer ->
                    writer.write(reportAdapter.toJson(report))
                }
                writeZipEntry(zip, "REPORT_FULL.md") { writer ->
                    streamDiagnosticMarkdown(writer, report, language)
                }
                writeZipEntry(zip, "metadata/environment.txt") { writer ->
                    writer.appendLine("Session ID: ${report.sessionId}")
                    writer.appendLine("Mode: ${report.mode}")
                    writer.appendLine("Timestamp: ${report.createdAtIso}")
                    writer.appendLine("Device: ${report.environment.deviceModel}")
                    writer.appendLine("Android: ${report.environment.androidRelease} (SDK ${report.environment.sdkInt})")
                    writer.appendLine("Build Fingerprint: ${report.environment.buildFingerprint}")
                    writer.appendLine("Boot Signature: ${report.environment.bootSignature}")
                    writer.appendLine("Vendor Fingerprint: ${report.environment.vendorFingerprint}")
                    writer.appendLine("GSI Suspected: ${report.environment.isGsiSuspected} -> ${report.environment.gsiIndicators}")
                    writer.appendLine("SELinux: ${report.environment.selinuxMode}")
                    writer.appendLine("Root Requested/Granted: ${report.environment.rootRequested}/${report.environment.rootGranted}")
                    writer.appendLine("Biometric Hardware: ${report.environment.biometricHardwareStatus}")
                    writer.appendLine("Display Modes: ${report.environment.displayModesSummary}")
                    writer.appendLine("Access Limitations:")
                    report.environment.accessLimitations.forEach { writer.appendLine("  - $it") }
                }
                writeZipEntry(zip, "inventories/components_and_patches.txt") { writer ->
                    writer.appendLine("=== COMPONENTS (${report.components.size}) ===")
                    report.components.forEach {
                        writer.appendLine("[${it.status}/${it.knowledgeLevel}] ${it.category} | ${it.name} | ver=${it.version} | iface=${it.interfaceType} | path=${it.path} | note=${it.accessNote ?: ""}")
                    }
                    writer.appendLine("\n=== PATCHES & OVERLAYS (${report.patches.size}) ===")
                    report.patches.forEach {
                        writer.appendLine("[${it.status}] ${it.scope} | ${it.name}=${it.rawValue} | effect=${it.realObservedEffect}")
                    }
                    writer.appendLine("\n=== DEPENDENCY GRAPH EDGES (${report.dependencyEdges.size}) ===")
                    report.dependencyEdges.forEach {
                        writer.appendLine("${it.fromId} --(${it.relation} [${it.status}])--> ${it.toId} | ${it.note}")
                    }
                }
                writeZipEntry(zip, "disassembly/elf_disassembly_full.txt") { writer ->
                    writer.write(report.rawArtifacts.elfDisassemblyFull)
                }
                writeRawEntry(zip, "raw/logcat_enrollment.txt", report.rawArtifacts.logcatEnrollment)
                writeRawEntry(zip, "raw/logcat_baseline.txt", report.rawArtifacts.logcatBaseline)
                writeRawEntry(zip, "raw/dumpsys_fingerprint.txt", report.rawArtifacts.dumpsysFingerprint)
                writeRawEntry(zip, "raw/dumpsys_biometric.txt", report.rawArtifacts.dumpsysBiometric)
                writeRawEntry(zip, "raw/dumpsys_surfaceflinger.txt", report.rawArtifacts.dumpsysSurfaceFlinger)
                writeRawEntry(zip, "raw/dumpsys_display.txt", report.rawArtifacts.dumpsysDisplay)
                writeRawEntry(zip, "raw/dumpsys_overlay.txt", report.rawArtifacts.dumpsysOverlay)
                writeRawEntry(zip, "raw/lshal.txt", report.rawArtifacts.lshalOutput)
                writeRawEntry(zip, "raw/vintf_manifests.txt", report.rawArtifacts.vintfManifests)
                writeRawEntry(zip, "raw/service_list.txt", report.rawArtifacts.serviceList)
                writeRawEntry(zip, "raw/getprop_all.txt", report.rawArtifacts.getpropAll)
                writeRawEntry(zip, "raw/sysfs_fod_nodes.txt", report.rawArtifacts.sysfsFodNodes)
                writeRawEntry(zip, "raw/selinux_denials.txt", report.rawArtifacts.selinuxDenials)
                writeRawEntry(zip, "raw/init_rc_snippets.txt", report.rawArtifacts.initRcSnippets)
                writeRawEntry(zip, "raw/dmesg_delta.txt", report.rawArtifacts.dmesgDelta)
                writeRawEntry(zip, "raw/surfaceflinger_live_delta.txt", report.rawArtifacts.surfaceFlingerLiveDelta)
                writeRawEntry(zip, "raw/overlay_deep_inspect.txt", report.rawArtifacts.overlayDeepInspect)
                writeRawEntry(zip, "raw/file_provenance_index.txt", report.rawArtifacts.fileProvenanceIndex)
                writeRawEntry(zip, "raw/proc_live_maps.txt", report.rawArtifacts.procLiveMaps)
                writeRawEntry(zip, "raw/dex_source_extract.txt", report.rawArtifacts.dexSourceExtract)
                writeRawEntry(zip, "raw/binder_trace_delta.txt", report.rawArtifacts.binderTraceDelta)
            }
        }
        label
    }

    suspend fun exportDiagnosticSingleFile(
        context: Context,
        report: FodDiagnosticReport,
        language: AppLanguage,
        asHtml: Boolean,
        targetUri: Uri?,
        directFileName: String? = null
    ): String = withContext(Dispatchers.IO) {
        val ext = if (asHtml) "html" else "md"
        val defaultName = "fod_dossier_${report.mode.name.lowercase()}_${report.sessionId}.$ext"
        val (stream, label) = openTargetOutput(context, targetUri, directFileName ?: defaultName)
        stream.use { out ->
            BufferedWriter(OutputStreamWriter(out, Charsets.UTF_8), 64 * 1024).use { writer ->
                if (asHtml) {
                    streamDiagnosticHtml(writer, report, language)
                } else {
                    streamDiagnosticMarkdown(writer, report, language)
                }
                writer.flush()
            }
        }
        label
    }

    suspend fun exportComparisonSingleFile(
        context: Context,
        comparison: ComparisonResult,
        rom: FodDiagnosticReport,
        gsi: FodDiagnosticReport,
        language: AppLanguage,
        asHtml: Boolean,
        targetUri: Uri?,
        directFileName: String? = null
    ): String = withContext(Dispatchers.IO) {
        val ext = if (asHtml) "html" else "md"
        val defaultName = "fod_comparison_${comparison.romSessionId}_vs_${comparison.gsiSessionId}.$ext"
        val (stream, label) = openTargetOutput(context, targetUri, directFileName ?: defaultName)
        stream.use { out ->
            BufferedWriter(OutputStreamWriter(out, Charsets.UTF_8), 64 * 1024).use { writer ->
                if (asHtml) {
                    streamComparisonHtml(writer, comparison, rom, gsi, language)
                } else {
                    streamComparisonMarkdown(writer, comparison, rom, gsi, language)
                }
                writer.flush()
            }
        }
        label
    }

    suspend fun exportPortSingleFile(
        context: Context,
        portResult: PortAnalysisResult,
        romZip: RawZipArchiveBundle,
        gsiZip: RawZipArchiveBundle,
        language: AppLanguage,
        asHtml: Boolean,
        targetUri: Uri?,
        directFileName: String? = null
    ): String = withContext(Dispatchers.IO) {
        val ext = if (asHtml) "html" else "md"
        val stamp = portResult.createdAtIso.replace(":", "").replace("-", "").take(15)
        val defaultName = "fod_port_dossier_$stamp.$ext"
        val (stream, label) = openTargetOutput(context, targetUri, directFileName ?: defaultName)
        stream.use { out ->
            BufferedWriter(OutputStreamWriter(out, Charsets.UTF_8), 64 * 1024).use { writer ->
                if (asHtml) {
                    streamPortHtml(writer, portResult, romZip, gsiZip, language)
                } else {
                    streamPortMarkdown(writer, portResult, romZip, gsiZip, language)
                }
                writer.flush()
            }
        }
        label
    }

    suspend fun importReportFromZip(
        context: Context,
        uri: Uri
    ): FodDiagnosticReport = withContext(Dispatchers.IO) {
        context.contentResolver.openInputStream(uri)?.use { input ->
            parseReportFromZipStream(input)
        } ?: throw IllegalStateException("Cannot open input stream for $uri")
    }

    fun parseReportFromZipStream(input: InputStream): FodDiagnosticReport {
        ZipInputStream(input).use { zip ->
            var entry = zip.nextEntry
            while (entry != null) {
                if (entry.name == "report.json") {
                    val json = zip.readBytes().toString(Charsets.UTF_8)
                    return reportAdapter.fromJson(json)
                        ?: throw IllegalStateException("Invalid report.json inside ZIP")
                }
                zip.closeEntry()
                entry = zip.nextEntry
            }
        }
        throw IllegalStateException("Archive does not contain report.json")
    }

    private fun openTargetOutput(
        context: Context,
        targetUri: Uri?,
        fallbackFileName: String
    ): Pair<OutputStream, String> {
        if (targetUri != null) {
            val os = context.contentResolver.openOutputStream(targetUri)
                ?: throw IllegalStateException("Unable to open SAF output stream")
            return os to (targetUri.lastPathSegment ?: fallbackFileName)
        }
        val file = File(defaultDirectDirectory(), fallbackFileName)
        return FileOutputStream(file) to file.absolutePath
    }

    private inline fun writeZipEntry(
        zip: ZipOutputStream,
        name: String,
        block: (BufferedWriter) -> Unit
    ) {
        zip.putNextEntry(ZipEntry(name))
        val writer = BufferedWriter(OutputStreamWriter(zip, Charsets.UTF_8), 32 * 1024)
        block(writer)
        writer.flush()
        zip.closeEntry()
    }

    private fun writeRawEntry(zip: ZipOutputStream, name: String, content: String) {
        zip.putNextEntry(ZipEntry(name))
        zip.write(content.toByteArray(Charsets.UTF_8))
        zip.closeEntry()
    }

    private fun streamDiagnosticMarkdown(
        w: BufferedWriter,
        r: FodDiagnosticReport,
        lang: AppLanguage
    ) {
        w.appendLine("# FOD DETECTOR — COMPLETE FORENSIC DOSSIER (${r.mode})")
        w.appendLine("- **Session ID**: `${r.sessionId}`")
        w.appendLine("- **Timestamp**: `${r.createdAtIso}`")
        w.appendLine("- **Device**: `${r.environment.deviceModel}` (Android ${r.environment.androidRelease}, SDK ${r.environment.sdkInt})")
        w.appendLine("- **Boot Signature**: `${r.environment.bootSignature}`")
        w.appendLine("- **Vendor Fingerprint**: `${r.environment.vendorFingerprint}`")
        w.appendLine("- **GSI Indicators**: `${r.environment.gsiIndicators}`")
        w.appendLine("- **SELinux / Root**: `${r.environment.selinuxMode}` / Root=${r.environment.rootGranted}")
        w.appendLine("- **Outcome**: **${r.summary.overallOutcome}**")
        w.appendLine("- **First Break**: `${r.summary.firstDemonstratedBreak}`")
        w.appendLine("- **Noise vs Success**: `${r.summary.realSuccessDespiteNoiseNote}`")
        w.appendLine()

        if (r.environment.accessLimitations.isNotEmpty()) {
            w.appendLine("## Access Limitations (Strictly Reported)")
            r.environment.accessLimitations.forEach { w.appendLine("- $it") }
            w.appendLine()
        }

        if (r.summary.aiThinkingSynthesis.isNotBlank()) {
            w.appendLine("## Gemini 4 Carbon (High Thinking) Synthesis")
            w.appendLine(r.summary.aiThinkingSynthesis)
            w.appendLine()
        }

        if (r.fingerDownChain.isNotEmpty()) {
            w.appendLine("## 0. FINGER-DOWN EXECUTION CHAIN (${r.fingerDownChain.size} stages)")
            r.fingerDownChain.forEach { s ->
                w.appendLine("- **[${s.status}] ${s.stage}**: ${s.detail}")
                if (s.evidence.isNotBlank()) w.appendLine("  - Evidence: `${s.evidence}`")
            }
            w.appendLine()
        }

        if (r.sysfsTransitions.isNotEmpty()) {
            w.appendLine("## 0b. SYSFS TRANSITIONS (T0 -> T_live -> T1)")
            r.sysfsTransitions.forEach { t ->
                w.appendLine("- **[changed=${t.changed}]** `${t.nodePath}`: `${t.beforeValue}` -> ${t.liveValues} -> `${t.afterValue}`")
            }
            w.appendLine()
        }

        if (r.causalChain.isNotEmpty()) {
            w.appendLine("## 0c. END-TO-END CAUSAL FOD CHAIN (${r.causalChain.size} layers | ${r.filteredNonFodOverlayCount} non-FOD RROs filtered)")
            r.causalChain.forEach { link ->
                w.appendLine("- **[${link.status}] ${link.title}** (`${link.proofKind}`) · `${link.sourceFile}`")
                if (link.referencedResourceKeys.isNotEmpty()) {
                    w.appendLine("  - Keys/Symbols: `${link.referencedResourceKeys.joinToString(", ")}`")
                }
                if (link.liveRuntimeEvidence.isNotBlank()) {
                    w.appendLine("  - Live: `${link.liveRuntimeEvidence.replace("\n", " | ")}`")
                }
                if (link.breakExplanation.isNotBlank()) {
                    w.appendLine("  - Break: ${link.breakExplanation}")
                }
                if (link.codeExcerpt.isNotBlank()) {
                    w.appendLine("  ```text\n${link.codeExcerpt}\n  ```")
                }
            }
            w.appendLine()
        }

        w.appendLine("## 1. SESSION FLOW (${r.sessionFlow.size} events)")
        r.sessionFlow.forEach { e ->
            w.appendLine("- [${e.status} | ${e.knowledgeLevel}] `${e.timestamp}` **${e.phase}** (${e.component}) benign=${e.isBenignWarning} blocking=${e.isBlockingFailure}")
            w.appendLine("  ```")
            w.appendLine("  ${e.rawEvidence}")
            w.appendLine("  ```")
        }
        w.appendLine()

        w.appendLine("## 2. COMPONENT INTELLIGENCE (${r.components.size})")
        r.components.forEach { c ->
            w.appendLine("- **[${c.status} | ${c.knowledgeLevel}]** `${c.category}` **${c.name}** | ver=`${c.version}` | iface=`${c.interfaceType}` | path=`${c.path}`")
            if (c.dependencies.isNotEmpty()) w.appendLine("  - deps: `${c.dependencies.joinToString(", ")}`")
            if (c.accessNote != null) w.appendLine("  - note: ${c.accessNote}")
        }
        w.appendLine()

        w.appendLine("## 3. PATCHES, PROPS & OVERLAYS (${r.patches.size})")
        r.patches.forEach { p ->
            w.appendLine("- **[${p.status}]** `${p.scope}` **${p.name}** = `${p.rawValue}` → ${p.realObservedEffect}")
        }
        w.appendLine()

        w.appendLine("## 4. DEPENDENCY GRAPH (${r.dependencyEdges.size} edges)")
        r.dependencyEdges.forEach { edge ->
            w.appendLine("- `${edge.fromId}` --[${edge.relation} / ${edge.status}]--> `${edge.toId}` (${edge.note})")
        }
        w.appendLine()

        w.appendLine("## 5. ELF DISASSEMBLY & BINARIES (${r.elfAnalyses.size})")
        w.appendLine("```text")
        w.appendLine(r.rawArtifacts.elfDisassemblyFull)
        w.appendLine("```")
        w.appendLine()

        if (r.procLiveMaps.isNotEmpty()) {
            w.appendLine("## 5b. LIVE ROOT PROCESSES (/proc/<pid>/maps & fd) (${r.procLiveMaps.size})")
            r.procLiveMaps.forEach { rec ->
                w.appendLine("- **${rec.processName}** (`pid=${rec.pid}`): matchedFod=${rec.matchedFodPaths.size}, newMaps=${rec.enrollmentNewMappedFiles.size}, newFds=${rec.enrollmentNewFds.size}")
                rec.matchedFodPaths.take(15).forEach { p -> w.appendLine("  - FOD_MATCH: `$p`") }
                rec.enrollmentNewMappedFiles.take(10).forEach { p -> w.appendLine("  - ENROLL_NEW_MAP: `$p`") }
                rec.enrollmentNewFds.take(10).forEach { p -> w.appendLine("  - ENROLL_NEW_FD: `$p`") }
            }
            w.appendLine()
        }

        if (r.dexSourceExtracts.isNotEmpty()) {
            w.appendLine("## 5c. DEX SOURCE-LEVEL & BYTECODE EXTRACTS (${r.dexSourceExtracts.size})")
            r.dexSourceExtracts.forEach { dex ->
                w.appendLine("### `${dex.archivePath}` (${dex.targetHint}) [${dex.containerType}]")
                if (dex.resolvedResourceKeys.isNotEmpty()) {
                    w.appendLine("- Resolved Resource Keys: `${dex.resolvedResourceKeys.joinToString(", ")}`")
                }
                dex.methodTraces.take(15).forEach { tr ->
                    w.appendLine("- Trace `${tr.fqMethod}` → calls: `${tr.invokedMethods.take(6).joinToString(", ")}` | res: `${tr.resolvedResKeys.joinToString(", ")}`")
                }
                w.appendLine("```kotlin")
                w.appendLine(dex.sourcePseudoSummary)
                w.appendLine("```")
            }
            w.appendLine()
        }

        val scoredOverlays = r.overlayInspections.filter { it.isStrictProvenFod || it.fodRelevanceScore > 0 || it.decodedArscEntries.isNotEmpty() || it.pseudoXmlSource.isNotBlank() }
        if (scoredOverlays.isNotEmpty() || r.filteredNonFodOverlayCount > 0) {
            w.appendLine("## 5d. STRICT PROVEN FOD RRO OVERLAYS (${scoredOverlays.size} proven · ${r.filteredNonFodOverlayCount} non-FOD filtered)")
            scoredOverlays.take(20).forEach { ov ->
                w.appendLine("### `${ov.packageName}` (strict=${ov.isStrictProvenFod}, score=${ov.fodRelevanceScore}, live=${ov.provenInLiveMaps}, apk=`${ov.apkPath}`)")
                ov.bytecodeMatchedResourceKeys.forEach { w.appendLine("- BYTECODE_R_ID_MATCH: `$it`") }
                if (ov.lookupWinners.isNotEmpty()) {
                    ov.lookupWinners.forEach { w.appendLine("- LOOKUP_WINNER: `$it`") }
                }
                ov.decodedArscEntries.take(25).forEach { w.appendLine("- `$it`") }
                if (ov.pseudoXmlSource.isNotBlank()) {
                    w.appendLine("```xml")
                    w.appendLine(ov.pseudoXmlSource)
                    w.appendLine("```")
                }
            }
            w.appendLine()
        }

        if (r.binderTraces.isNotEmpty()) {
            w.appendLine("## 5e. BINDER TRANSACTIONS & HAL IPC LINKS (${r.binderTraces.size})")
            r.binderTraces.forEach { bt ->
                w.appendLine("- **${bt.processName}** (pid=${bt.pid}): nodes=${bt.incomingNodes}, refs=${bt.outgoingRefs}")
                bt.linkedPeerProcesses.take(10).forEach { w.appendLine("  - PEER: `$it`") }
                bt.activeTransactions.take(10).forEach { w.appendLine("  - TX: `$it`") }
            }
            w.appendLine()
        }

        w.appendLine("## 6. FULL UNTRUNCATED RAW ARTIFACTS")
        val rawBlocks = listOf(
            "logcat_enrollment" to r.rawArtifacts.logcatEnrollment,
            "logcat_baseline" to r.rawArtifacts.logcatBaseline,
            "dumpsys_fingerprint" to r.rawArtifacts.dumpsysFingerprint,
            "dumpsys_biometric" to r.rawArtifacts.dumpsysBiometric,
            "dumpsys_surfaceflinger" to r.rawArtifacts.dumpsysSurfaceFlinger,
            "dumpsys_display" to r.rawArtifacts.dumpsysDisplay,
            "dumpsys_overlay" to r.rawArtifacts.dumpsysOverlay,
            "lshal" to r.rawArtifacts.lshalOutput,
            "vintf_manifests" to r.rawArtifacts.vintfManifests,
            "service_list" to r.rawArtifacts.serviceList,
            "sysfs_fod_nodes" to r.rawArtifacts.sysfsFodNodes,
            "dmesg_delta" to r.rawArtifacts.dmesgDelta,
            "surfaceflinger_live_delta" to r.rawArtifacts.surfaceFlingerLiveDelta,
            "selinux_denials" to r.rawArtifacts.selinuxDenials,
            "init_rc_snippets" to r.rawArtifacts.initRcSnippets,
            "overlay_deep_inspect" to r.rawArtifacts.overlayDeepInspect,
            "file_provenance_index" to r.rawArtifacts.fileProvenanceIndex,
            "proc_live_maps" to r.rawArtifacts.procLiveMaps,
            "dex_source_extract" to r.rawArtifacts.dexSourceExtract,
            "binder_trace_delta" to r.rawArtifacts.binderTraceDelta,
            "getprop_all" to r.rawArtifacts.getpropAll
        )
        rawBlocks.forEach { (title, body) ->
            w.appendLine("### $title")
            w.appendLine("```text")
            w.appendLine(body)
            w.appendLine("```")
            w.appendLine()
        }
    }

    private fun streamDiagnosticHtml(
        w: BufferedWriter,
        r: FodDiagnosticReport,
        lang: AppLanguage
    ) {
        writeHtmlHeader(w, "FOD Detector — ${r.mode} (${r.sessionId})")
        w.appendLine("<h1>FOD DETECTOR · ${esc(r.mode.name)} · ${esc(r.sessionId)}</h1>")
        w.appendLine("<div class='card'>")
        w.appendLine("<p><b>Device:</b> ${esc(r.environment.deviceModel)} | Android ${esc(r.environment.androidRelease)} (SDK ${r.environment.sdkInt})</p>")
        w.appendLine("<p><b>Boot:</b> <code>${esc(r.environment.bootSignature)}</code></p>")
        w.appendLine("<p><b>Vendor:</b> <code>${esc(r.environment.vendorFingerprint)}</code></p>")
        w.appendLine("<p><b>Outcome:</b> <span class='badge'>${esc(r.summary.overallOutcome)}</span></p>")
        w.appendLine("<p><b>First Break:</b> ${esc(r.summary.firstDemonstratedBreak)}</p>")
        w.appendLine("<p><b>Noise Analysis:</b> ${esc(r.summary.realSuccessDespiteNoiseNote)}</p>")
        w.appendLine("</div>")

        if (r.summary.aiThinkingSynthesis.isNotBlank()) {
            w.appendLine("<h2>Gemini 4 Carbon · High Thinking Synthesis</h2><pre>${esc(r.summary.aiThinkingSynthesis)}</pre>")
        }

        w.appendLine("<h2>SESSION FLOW (${r.sessionFlow.size})</h2><ul>")
        r.sessionFlow.forEach { e ->
            w.appendLine("<li><b>[${e.status}] ${esc(e.phase)}</b> (${esc(e.component)}): <code>${esc(e.rawEvidence)}</code></li>")
        }
        w.appendLine("</ul>")

        w.appendLine("<h2>COMPONENT INTELLIGENCE (${r.components.size})</h2><ul>")
        r.components.forEach { c ->
            w.appendLine("<li><b>[${c.status}] ${esc(c.category.name)}</b> ${esc(c.name)} — <code>${esc(c.path)}</code> (${esc(c.version)} / ${esc(c.interfaceType)})</li>")
        }
        w.appendLine("</ul>")

        w.appendLine("<h2>PATCHES & OVERLAYS (${r.patches.size})</h2><ul>")
        r.patches.forEach { p ->
            w.appendLine("<li><b>[${p.status}] ${esc(p.scope)}</b> ${esc(p.name)} = <code>${esc(p.rawValue)}</code> → ${esc(p.realObservedEffect)}</li>")
        }
        w.appendLine("</ul>")

        writeHtmlDetails(w, "ELF Disassembly & Binaries", r.rawArtifacts.elfDisassemblyFull)
        writeHtmlDetails(w, "RAW: logcat_enrollment", r.rawArtifacts.logcatEnrollment)
        writeHtmlDetails(w, "RAW: dumpsys_fingerprint", r.rawArtifacts.dumpsysFingerprint)
        writeHtmlDetails(w, "RAW: dumpsys_biometric", r.rawArtifacts.dumpsysBiometric)
        writeHtmlDetails(w, "RAW: dumpsys_surfaceflinger", r.rawArtifacts.dumpsysSurfaceFlinger)
        writeHtmlDetails(w, "RAW: dumpsys_display", r.rawArtifacts.dumpsysDisplay)
        writeHtmlDetails(w, "RAW: dumpsys_overlay", r.rawArtifacts.dumpsysOverlay)
        writeHtmlDetails(w, "RAW: lshal", r.rawArtifacts.lshalOutput)
        writeHtmlDetails(w, "RAW: vintf_manifests", r.rawArtifacts.vintfManifests)
        writeHtmlDetails(w, "RAW: service_list", r.rawArtifacts.serviceList)
        writeHtmlDetails(w, "RAW: sysfs_fod_nodes", r.rawArtifacts.sysfsFodNodes)
        writeHtmlDetails(w, "RAW: selinux_denials", r.rawArtifacts.selinuxDenials)
        writeHtmlDetails(w, "RAW: init_rc", r.rawArtifacts.initRcSnippets)
        if (r.fingerDownChain.isNotEmpty()) {
            w.appendLine("<h2>FINGER-DOWN EXECUTION CHAIN</h2><ul>")
            r.fingerDownChain.forEach { s ->
                w.appendLine("<li><b>[${s.status}] ${esc(s.stage)}</b>: ${esc(s.detail)}</li>")
            }
            w.appendLine("</ul>")
        }
        if (r.sysfsTransitions.isNotEmpty()) {
            w.appendLine("<h2>SYSFS TRANSITIONS (Before → Live → After)</h2><ul>")
            r.sysfsTransitions.forEach { t ->
                w.appendLine("<li><b>[changed=${t.changed}]</b> <code>${esc(t.nodePath)}</code>: <code>${esc(t.beforeValue)}</code> → <code>${esc(t.liveValues.toString())}</code> → <code>${esc(t.afterValue)}</code></li>")
            }
            w.appendLine("</ul>")
        }
        if (r.causalChain.isNotEmpty()) {
            w.appendLine("<h2>END-TO-END CAUSAL FOD CHAIN (${r.causalChain.size} layers · ${r.filteredNonFodOverlayCount} non-FOD overlays filtered)</h2><ul>")
            r.causalChain.forEach { link ->
                w.appendLine("<li><b>[${link.status}] ${esc(link.title)}</b> (${esc(link.proofKind)}) — <code>${esc(link.sourceFile)}</code>")
                if (link.breakExplanation.isNotBlank()) w.appendLine("<br/><i>${esc(link.breakExplanation)}</i>")
                if (link.codeExcerpt.isNotBlank()) w.appendLine("<pre>${esc(link.codeExcerpt)}</pre>")
                w.appendLine("</li>")
            }
            w.appendLine("</ul>")
        }
        writeHtmlDetails(w, "RAW: dmesg_delta", r.rawArtifacts.dmesgDelta)
        writeHtmlDetails(w, "RAW: surfaceflinger_live_delta", r.rawArtifacts.surfaceFlingerLiveDelta)
        writeHtmlDetails(w, "RAW: overlay_deep_inspect", r.rawArtifacts.overlayDeepInspect)
        writeHtmlDetails(w, "RAW: file_provenance_index", r.rawArtifacts.fileProvenanceIndex)
        writeHtmlDetails(w, "RAW: proc_live_maps", r.rawArtifacts.procLiveMaps)
        writeHtmlDetails(w, "RAW: dex_source_extract", r.rawArtifacts.dexSourceExtract)
        writeHtmlDetails(w, "RAW: binder_trace_delta", r.rawArtifacts.binderTraceDelta)
        writeHtmlDetails(w, "RAW: getprop_all", r.rawArtifacts.getpropAll)
        w.appendLine("</body></html>")
    }

    private fun streamComparisonMarkdown(
        w: BufferedWriter,
        c: ComparisonResult,
        rom: FodDiagnosticReport,
        gsi: FodDiagnosticReport,
        lang: AppLanguage
    ) {
        w.appendLine("# FOD FORENSIC COMPARISON REPORT: CUSTOM ROM (${c.romSessionId}) vs GSI (${c.gsiSessionId})")
        w.appendLine("- **Invariant**: Same untouched `boot` and `vendor` partitions.")
        w.appendLine("- **Parity Verified**: `${c.bootVendorParityVerified}` (${c.bootVendorParitySummary})")
        w.appendLine()
        if (c.aiDeepComparisonMarkdown.isNotBlank()) {
            w.appendLine("## Gemini 4 Carbon (High Thinking) Deep Forensic Synthesis")
            w.appendLine(c.aiDeepComparisonMarkdown)
            w.appendLine()
        }
        val sections = listOf(
            "TRUE GSI DIFFERENTIAL BLOCKERS (Filtered)" to c.trueGsiBlockers,
            "Shared Non-Blocking Items (Missing/KO on Both)" to c.sharedNonBlockingItems,
            "Missing in GSI" to c.missingInGsi,
            "Configs, Overlays & Patches Diffs" to c.configAndPatchDiffs,
            "Missing Live Interactions" to c.missingLiveInteractions,
            "Demonstrated Breaks" to c.demonstratedBreaks,
            "Common Component Diffs" to c.commonComponentDiffs,
            "Version & Interface Diffs" to c.versionAndInterfaceDiffs,
            "Incompatible Libs & Services" to c.incompatibleLibsAndServices
        )
        sections.forEach { (title, list) ->
            w.appendLine("## $title (${list.size})")
            list.forEach { item ->
                w.appendLine("- **[${item.status}/${item.knowledgeLevel}] ${item.title}**")
                w.appendLine("  - ROM: `${item.romDetail}`")
                w.appendLine("  - GSI: `${item.gsiDetail}`")
                w.appendLine("  - Impact: ${item.impact}")
            }
            w.appendLine()
        }
        w.appendLine("## System-Level Remediation Options (No Vendor/Boot Modifications)")
        c.remediationOptions.forEach { r ->
            w.appendLine("- **[${r.status}] ${r.title}** (Framework/SystemUI required: `${r.requiresFrameworkOrSystemUi}`)")
            w.appendLine("  - Layer: `${r.layer}`")
            w.appendLine("  - Description: ${r.description}")
            w.appendLine("  - Evidence:\n```\n${r.supportingEvidence}\n```")
            w.appendLine("  - Limits: ${r.limitations}")
        }
        w.appendLine()
        w.appendLine("---")
        w.appendLine("# APPENDIX A: FULL CUSTOM ROM DOSSIER")
        streamDiagnosticMarkdown(w, rom, lang)
        w.appendLine("---")
        w.appendLine("# APPENDIX B: FULL GSI DOSSIER")
        streamDiagnosticMarkdown(w, gsi, lang)
    }

    private fun streamComparisonHtml(
        w: BufferedWriter,
        c: ComparisonResult,
        rom: FodDiagnosticReport,
        gsi: FodDiagnosticReport,
        lang: AppLanguage
    ) {
        writeHtmlHeader(w, "FOD Comparison: ${c.romSessionId} vs ${c.gsiSessionId}")
        w.appendLine("<h1>FOD FORENSIC COMPARISON: ROM (${esc(c.romSessionId)}) vs GSI (${esc(c.gsiSessionId)})</h1>")
        w.appendLine("<div class='card'><p><b>Invariant:</b> Identical untouched boot & vendor partitions</p>")
        w.appendLine("<p><b>Parity:</b> ${c.bootVendorParityVerified} — <code>${esc(c.bootVendorParitySummary)}</code></p></div>")
        if (c.aiDeepComparisonMarkdown.isNotBlank()) {
            w.appendLine("<h2>Gemini 4 Carbon · High Thinking Synthesis</h2><pre>${esc(c.aiDeepComparisonMarkdown)}</pre>")
        }
        val sections = listOf(
            "TRUE GSI DIFFERENTIAL BLOCKERS" to c.trueGsiBlockers,
            "Shared Non-Blocking Items (Missing/KO on Both)" to c.sharedNonBlockingItems,
            "Missing in GSI" to c.missingInGsi,
            "Patches, Configs & Overlays Diffs" to c.configAndPatchDiffs,
            "Missing Live Interactions" to c.missingLiveInteractions,
            "Demonstrated Breaks" to c.demonstratedBreaks,
            "Common Component Diffs" to c.commonComponentDiffs
        )
        sections.forEach { (title, entries) ->
            w.appendLine("<h2>${esc(title)} (${entries.size})</h2><ul>")
            entries.forEach { e ->
                w.appendLine("<li><b>[${e.status}] ${esc(e.title)}</b><br/>ROM: <code>${esc(e.romDetail)}</code><br/>GSI: <code>${esc(e.gsiDetail)}</code><br/><i>${esc(e.impact)}</i></li>")
            }
            w.appendLine("</ul>")
        }
        w.appendLine("<h2>System Remediation Roadmap</h2><ul>")
        c.remediationOptions.forEach { r ->
            w.appendLine("<li><b>${esc(r.title)}</b> (Framework/SystemUI=${r.requiresFrameworkOrSystemUi})<br/>${esc(r.description)}<pre>${esc(r.supportingEvidence)}</pre></li>")
        }
        w.appendLine("</ul>")
        writeHtmlDetails(w, "RAW Appendix: ROM logcat_enrollment", rom.rawArtifacts.logcatEnrollment)
        writeHtmlDetails(w, "RAW Appendix: GSI logcat_enrollment", gsi.rawArtifacts.logcatEnrollment)
        w.appendLine("</body></html>")
    }

    internal fun streamPortMarkdown(
        w: BufferedWriter,
        p: PortAnalysisResult,
        romZip: RawZipArchiveBundle,
        gsiZip: RawZipArchiveBundle,
        lang: AppLanguage
    ) {
        w.appendLine("# FOD DETECTOR — COMPLETE PORTING DOSSIER (CUSTOM ROM vs GSI)")
        w.appendLine("- **Generated**: `${p.createdAtIso}`")
        w.appendLine("- **ROM Archive**: `${p.romSourceName}` (${p.romFilesRead} files, ${p.romTotalBytes / 1024} KB)")
        w.appendLine("- **GSI Archive**: `${p.gsiSourceName}` (${p.gsiFilesRead} files, ${p.gsiTotalBytes / 1024} KB)")
        w.appendLine("- **Invariant**: Untouched shared `boot` and `vendor` partitions (GSI/system-side porting only).")
        w.appendLine("- **Boot/Vendor Parity**: `${p.bootVendorParityVerified}` (${p.bootVendorParitySummary})")
        w.appendLine("- **AI Engine**: `${p.aiProviderUsed.ifBlank { "Deterministic Local Engine" }}`")
        w.appendLine()
        w.appendLine("## 1. Factual Root-Cause Verdict")
        w.appendLine(p.factualRootCauseVerdict)
        if (p.causalBreakSummary.isNotBlank()) {
            w.appendLine("- **Causal Break**: ${p.causalBreakSummary}")
        }
        if (p.filteredNonFodOverlayCount > 0) {
            w.appendLine("- **Non-FOD Overlays Rejected**: ${p.filteredNonFodOverlayCount}")
        }
        w.appendLine()
        if (p.romCausalChain.isNotEmpty()) {
            w.appendLine("## 1b. Causal Chain Comparison (ROM vs GSI)")
            p.romCausalChain.forEachIndexed { idx, rLink ->
                val gLink = p.gsiCausalChain.getOrNull(idx)
                w.appendLine("- **${rLink.title}**: ROM=`${rLink.status}` (${rLink.sourceFile}) vs GSI=`${gLink?.status ?: "UNKNOWN"}` (${gLink?.sourceFile ?: "?"})")
                if (gLink != null && gLink.breakExplanation.isNotBlank()) {
                    w.appendLine("  - GSI Break: ${gLink.breakExplanation}")
                }
            }
            w.appendLine()
        }
        if (p.aiFactualSynthesis.isNotBlank()) {
            w.appendLine("## 2. 100% Factual AI & Porting Synthesis")
            w.appendLine(p.aiFactualSynthesis)
            w.appendLine()
        }
        w.appendLine("## 2b. ${if (lang == AppLanguage.FR) "Fichiers & Mécanismes à extraire du Custom ROM" else "Files & Mechanisms to Extract From Custom ROM"} (${p.extractableFiles.size})")
        if (p.extractableFiles.isEmpty()) {
            w.appendLine(if (lang == AppLanguage.FR) "- Aucun fichier extractible identifié." else "- No extractable files identified.")
        } else {
            p.extractableFiles.forEach { ex ->
                w.appendLine("### [${ex.category} · ${ex.priorityPercent}%] ${ex.title}")
                w.appendLine("- **ROM File Path**: `${ex.romFilePath}`")
                w.appendLine("- **ROM Directory**: `${ex.romDirectory}`")
                w.appendLine("- **Target GSI Path (vendor/boot untouched)**: `${ex.targetGsiPath}`")
                w.appendLine("- **GSI State**: `${ex.gsiCurrentState}`")
                w.appendLine("- **Missing Mechanism**: ${ex.missingMechanism}")
                if (ex.importantElements.isNotEmpty()) {
                    w.appendLine("- **Important Internal Contents**:")
                    ex.importantElements.forEach { el -> w.appendLine("  - `$el`") }
                }
                w.appendLine()
            }
        }
        w.appendLine("## 3. Ranked System-Side Porting Solutions (${p.portingSolutions.size})")
        p.portingSolutions.forEach { sol ->
            w.appendLine("### #${sol.rank} — ${sol.title} (${sol.confidencePercent}% confidence)")
            w.appendLine("- **Layer**: `${sol.layer}` | **Requires SystemUI/Framework**: `${sol.requiresFrameworkOrSystemUi}`")
            w.appendLine("- **Why**: ${sol.whyItApplies}")
            if (sol.exactSourcesInZip.isNotEmpty()) {
                w.appendLine("- **Exact ZIP Evidence**:")
                sol.exactSourcesInZip.forEach { src -> w.appendLine("  - `$src`") }
            }
            w.appendLine("- **Action Steps**:")
            sol.concreteActionSteps.forEachIndexed { idx, step -> w.appendLine("  ${idx + 1}. $step") }
            w.appendLine("- **Limitations**: ${sol.limitations}")
            w.appendLine()
        }
        w.appendLine("## 4. Exhaustive Multi-File Factual Diffs (${p.factualDiffs.size})")
        p.factualDiffs.forEach { d ->
            w.appendLine("- **[${d.status} | ${d.knowledgeLevel}] (${d.sourceFile}) ${d.category} :: ${d.title}**")
            w.appendLine("  - ROM: `${d.romEvidence.replace("\n", " | ")}`")
            w.appendLine("  - GSI: `${d.gsiEvidence.replace("\n", " | ")}`")
            w.appendLine("  - Impact: ${d.impact}")
        }
        w.appendLine()
        w.appendLine("## 5. Filtered Shared Non-Blocking Noise (${p.filteredSharedNoiseCount} total)")
        p.sharedNoiseSamples.forEach { n ->
            w.appendLine("- (${n.sourceFile}) ${n.title}: ${n.impact}")
        }
        w.appendLine()
        w.appendLine("## 6. Complete ZIP Entry Indexes")
        w.appendLine("### ROM ZIP (${romZip.totalFiles} entries)")
        romZip.entries.forEach { e ->
            w.appendLine("- `${e.path}` (${e.sizeBytes} bytes, ${e.lineCount} lines${if (e.truncatedInMemory) ", TRUNCATED" else ""})")
        }
        w.appendLine("### GSI ZIP (${gsiZip.totalFiles} entries)")
        gsiZip.entries.forEach { e ->
            w.appendLine("- `${e.path}` (${e.sizeBytes} bytes, ${e.lineCount} lines${if (e.truncatedInMemory) ", TRUNCATED" else ""})")
        }
        w.appendLine()
        w.appendLine("## 7. Full Raw ZIP Contents Appendix")
        romZip.rawFiles.forEach { (path, content) ->
            if (path == "report.json") return@forEach
            w.appendLine("### [ROM] $path")
            w.appendLine("```text")
            w.appendLine(content)
            w.appendLine("```")
        }
        gsiZip.rawFiles.forEach { (path, content) ->
            if (path == "report.json") return@forEach
            w.appendLine("### [GSI] $path")
            w.appendLine("```text")
            w.appendLine(content)
            w.appendLine("```")
        }
        w.flush()
    }

    internal fun streamPortHtml(
        w: BufferedWriter,
        p: PortAnalysisResult,
        romZip: RawZipArchiveBundle,
        gsiZip: RawZipArchiveBundle,
        lang: AppLanguage
    ) {
        writeHtmlHeader(w, "FOD Porting Dossier — ${p.romSourceName} vs ${p.gsiSourceName}")
        w.appendLine("<h1>FOD PORTING DOSSIER · CUSTOM ROM vs GSI</h1>")
        w.appendLine("<div class='card'>")
        w.appendLine("<p><b>ROM Archive:</b> ${esc(p.romSourceName)} (${p.romFilesRead} files, ${p.romTotalBytes / 1024} KB)</p>")
        w.appendLine("<p><b>GSI Archive:</b> ${esc(p.gsiSourceName)} (${p.gsiFilesRead} files, ${p.gsiTotalBytes / 1024} KB)</p>")
        w.appendLine("<p><b>Boot/Vendor Parity:</b> ${p.bootVendorParityVerified} — <code>${esc(p.bootVendorParitySummary)}</code></p>")
        w.appendLine("<p><b>AI Engine:</b> <span class='badge'>${esc(p.aiProviderUsed.ifBlank { "Local Forensic Engine" })}</span></p>")
        if (p.causalBreakSummary.isNotBlank()) {
            w.appendLine("<p><b>Causal Break:</b> ${esc(p.causalBreakSummary)} (${p.filteredNonFodOverlayCount} non-FOD RROs rejected)</p>")
        }
        w.appendLine("<pre>${esc(p.factualRootCauseVerdict)}</pre>")
        w.appendLine("</div>")

        if (p.romCausalChain.isNotEmpty()) {
            w.appendLine("<h2>Causal Chain Comparison (ROM vs GSI)</h2><ul>")
            p.romCausalChain.forEachIndexed { idx, rLink ->
                val gLink = p.gsiCausalChain.getOrNull(idx)
                w.appendLine("<li><b>${esc(rLink.title)}</b>: ROM=[${rLink.status}] (<code>${esc(rLink.sourceFile)}</code>) vs GSI=[${gLink?.status ?: "UNKNOWN"}] (<code>${esc(gLink?.sourceFile ?: "?")}</code>)</li>")
            }
            w.appendLine("</ul>")
        }

        if (p.aiFactualSynthesis.isNotBlank()) {
            w.appendLine("<h2>100% Factual AI &amp; Porting Synthesis</h2><pre>${esc(p.aiFactualSynthesis)}</pre>")
        }

        w.appendLine("<h2>${if (lang == AppLanguage.FR) "Fichiers &amp; Mécanismes à extraire du Custom ROM" else "Files &amp; Mechanisms to Extract From Custom ROM"} (${p.extractableFiles.size})</h2>")
        p.extractableFiles.forEach { ex ->
            w.appendLine("<div class='card'>")
            w.appendLine("<h3>[${esc(ex.category)} · ${ex.priorityPercent}%] ${esc(ex.title)}</h3>")
            w.appendLine("<p><b>ROM File:</b> <code>${esc(ex.romFilePath)}</code></p>")
            w.appendLine("<p><b>ROM Directory:</b> <code>${esc(ex.romDirectory)}</code></p>")
            w.appendLine("<p><b>Target GSI (boot/vendor untouched):</b> <code>${esc(ex.targetGsiPath)}</code></p>")
            w.appendLine("<p>${esc(ex.missingMechanism)}</p>")
            if (ex.importantElements.isNotEmpty()) {
                w.appendLine("<ul>")
                ex.importantElements.forEach { el -> w.appendLine("<li><code>${esc(el)}</code></li>") }
                w.appendLine("</ul>")
            }
            w.appendLine("</div>")
        }

        w.appendLine("<h2>Ranked GSI/System Porting Solutions (${p.portingSolutions.size})</h2>")
        p.portingSolutions.forEach { sol ->
            w.appendLine("<div class='card'>")
            w.appendLine("<h3>#${sol.rank} · ${esc(sol.title)} (${sol.confidencePercent}%)</h3>")
            w.appendLine("<p><b>Layer:</b> ${esc(sol.layer)} | <b>SystemUI/Framework Edit:</b> ${sol.requiresFrameworkOrSystemUi}</p>")
            w.appendLine("<p>${esc(sol.whyItApplies)}</p>")
            w.appendLine("<ul>")
            sol.concreteActionSteps.forEach { step -> w.appendLine("<li>${esc(step)}</li>") }
            w.appendLine("</ul>")
            if (sol.exactSourcesInZip.isNotEmpty()) {
                w.appendLine("<p><b>Evidence:</b></p><ul>")
                sol.exactSourcesInZip.forEach { src -> w.appendLine("<li><code>${esc(src)}</code></li>") }
                w.appendLine("</ul>")
            }
            w.appendLine("<p><i>Limits: ${esc(sol.limitations)}</i></p>")
            w.appendLine("</div>")
        }

        w.appendLine("<h2>Multi-File Factual Diffs (${p.factualDiffs.size})</h2><ul>")
        p.factualDiffs.forEach { d ->
            w.appendLine("<li><b>[${d.status}] (${esc(d.sourceFile)}) ${esc(d.title)}</b><br/>ROM: <code>${esc(d.romEvidence)}</code><br/>GSI: <code>${esc(d.gsiEvidence)}</code><br/><i>${esc(d.impact)}</i></li>")
        }
        w.appendLine("</ul>")

        w.appendLine("<h2>Filtered Shared Non-Blocking Noise (${p.filteredSharedNoiseCount})</h2><ul>")
        p.sharedNoiseSamples.take(60).forEach { n ->
            w.appendLine("<li>(${esc(n.sourceFile)}) <b>${esc(n.title)}</b>: ${esc(n.impact)}</li>")
        }
        w.appendLine("</ul>")

        w.appendLine("<h2>Raw ZIP File Indexes &amp; Artifacts</h2>")
        romZip.rawFiles.forEach { (path, content) ->
            if (path != "report.json") writeHtmlDetails(w, "[ROM] $path", content)
        }
        gsiZip.rawFiles.forEach { (path, content) ->
            if (path != "report.json") writeHtmlDetails(w, "[GSI] $path", content)
        }
        w.appendLine("</body></html>")
        w.flush()
    }

    private fun writeHtmlHeader(w: BufferedWriter, title: String) {
        w.appendLine(
            """
            <!DOCTYPE html>
            <html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
            <title>${esc(title)}</title>
            <style>
              body{font-family:system-ui,-apple-system,sans-serif;margin:24px;line-height:1.5;background:#f8fafc;color:#0f172a;}
              @media(prefers-color-scheme:dark){body{background:#0a0f1a;color:#e2e8f0;}.card,pre,details{background:#111927;border-color:#28364f;}}
              .card,details{border:1px solid #cbd5e1;border-radius:10px;padding:14px;margin:12px 0;background:#fff;}
              pre,code{font-family:ui-monospace,monospace;font-size:12px;white-space:pre-wrap;word-break:break-word;}
              pre{padding:12px;border-radius:8px;border:1px solid #cbd5e1;overflow-x:auto;}
              .badge{padding:3px 8px;border-radius:6px;background:#0284c7;color:#fff;font-weight:600;}
              summary{cursor:pointer;font-weight:600;}
            </style></head><body>
            """.trimIndent()
        )
    }

    private fun writeHtmlDetails(w: BufferedWriter, title: String, content: String) {
        w.appendLine("<details><summary>${esc(title)} (${content.length} chars)</summary><pre>${esc(content)}</pre></details>")
    }

    private fun esc(s: String): String = s
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
}
