package com.example.engine

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import com.example.model.FodDiagnosticReport
import com.example.model.RawZipArchiveBundle
import com.example.model.ZipEntryDetail
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.util.zip.ZipInputStream

object PortZipDeepReader {

    private const val MAX_SINGLE_ENTRY_CHARS = 3 * 1024 * 1024 // 3 MB per single raw text entry

    private val moshi: Moshi = Moshi.Builder()
        .addLast(KotlinJsonAdapterFactory())
        .build()

    private val reportAdapter = moshi.adapter(FodDiagnosticReport::class.java)

    suspend fun readCompleteZip(
        context: Context,
        uri: Uri,
        archiveLabel: String
    ): RawZipArchiveBundle = withContext(Dispatchers.IO) {
        val displayName = resolveFileName(context, uri) ?: "$archiveLabel.zip"
        context.contentResolver.openInputStream(uri)?.use { stream ->
            readCompleteZipStream(stream, archiveLabel, displayName)
        } ?: throw IllegalStateException("Cannot open ZIP archive: $uri")
    }

    fun readCompleteZipStream(
        input: InputStream,
        archiveLabel: String,
        sourceName: String
    ): RawZipArchiveBundle {
        val entries = mutableListOf<ZipEntryDetail>()
        val rawFiles = LinkedHashMap<String, String>()
        var parsedReport: FodDiagnosticReport? = null

        ZipInputStream(input).use { zip ->
            val buffer = ByteArray(16 * 1024)
            var entry = zip.nextEntry
            while (entry != null) {
                if (!entry.isDirectory) {
                    val out = ByteArrayOutputStream()
                    var totalBytes = 0L
                    var truncated = false
                    while (true) {
                        val r = zip.read(buffer)
                        if (r <= 0) break
                        totalBytes += r
                        if (out.size() < MAX_SINGLE_ENTRY_CHARS) {
                            val remaining = MAX_SINGLE_ENTRY_CHARS - out.size()
                            out.write(buffer, 0, minOf(r, remaining))
                        } else {
                            truncated = true
                        }
                    }
                    val text = out.toString(Charsets.UTF_8.name())
                    val lines = if (text.isEmpty()) 0 else text.lineSequence().count()
                    entries += ZipEntryDetail(
                        path = entry.name,
                        sizeBytes = totalBytes,
                        lineCount = lines,
                        truncatedInMemory = truncated
                    )
                    rawFiles[entry.name] = text
                    if (entry.name == "report.json") {
                        parsedReport = runCatching { reportAdapter.fromJson(text) }.getOrNull()
                    }
                }
                zip.closeEntry()
                entry = zip.nextEntry
            }
        }

        if (entries.isEmpty()) {
            throw IllegalStateException("The selected ZIP archive '$sourceName' is empty or invalid.")
        }

        return RawZipArchiveBundle(
            archiveLabel = archiveLabel,
            sourceName = sourceName,
            report = parsedReport,
            entries = entries.sortedBy { it.path },
            rawFiles = rawFiles
        )
    }

    fun fromSavedReport(report: FodDiagnosticReport, archiveLabel: String): RawZipArchiveBundle {
        val rawFiles = linkedMapOf(
            "metadata/environment.txt" to "Mode=${report.mode}\nDevice=${report.environment.deviceModel}\nBoot=${report.environment.bootSignature}\nVendor=${report.environment.vendorFingerprint}\nSELinux=${report.environment.selinuxMode}",
            "raw/getprop_all.txt" to report.rawArtifacts.getpropAll,
            "raw/dumpsys_fingerprint.txt" to report.rawArtifacts.dumpsysFingerprint,
            "raw/dumpsys_biometric.txt" to report.rawArtifacts.dumpsysBiometric,
            "raw/dumpsys_surfaceflinger.txt" to report.rawArtifacts.dumpsysSurfaceFlinger,
            "raw/dumpsys_display.txt" to report.rawArtifacts.dumpsysDisplay,
            "raw/dumpsys_overlay.txt" to report.rawArtifacts.dumpsysOverlay,
            "raw/lshal.txt" to report.rawArtifacts.lshalOutput,
            "raw/vintf_manifests.txt" to report.rawArtifacts.vintfManifests,
            "raw/service_list.txt" to report.rawArtifacts.serviceList,
            "raw/sysfs_fod_nodes.txt" to report.rawArtifacts.sysfsFodNodes,
            "raw/selinux_denials.txt" to report.rawArtifacts.selinuxDenials,
            "raw/init_rc_snippets.txt" to report.rawArtifacts.initRcSnippets,
            "raw/dmesg_delta.txt" to report.rawArtifacts.dmesgDelta,
            "raw/surfaceflinger_live_delta.txt" to report.rawArtifacts.surfaceFlingerLiveDelta,
            "raw/logcat_enrollment.txt" to report.rawArtifacts.logcatEnrollment,
            "raw/overlay_deep_inspect.txt" to report.rawArtifacts.overlayDeepInspect,
            "raw/file_provenance_index.txt" to report.rawArtifacts.fileProvenanceIndex,
            "raw/proc_live_maps.txt" to report.rawArtifacts.procLiveMaps,
            "raw/dex_source_extract.txt" to report.rawArtifacts.dexSourceExtract,
            "raw/binder_trace_delta.txt" to report.rawArtifacts.binderTraceDelta,
            "disassembly/elf_disassembly_full.txt" to report.rawArtifacts.elfDisassemblyFull
        ).filterValues { it.isNotBlank() }

        val entries = rawFiles.map { (k, v) ->
            ZipEntryDetail(
                path = k,
                sizeBytes = v.toByteArray(Charsets.UTF_8).size.toLong(),
                lineCount = v.lineSequence().count(),
                truncatedInMemory = false
            )
        }
        return RawZipArchiveBundle(
            archiveLabel = archiveLabel,
            sourceName = "Session locale (${report.mode.name} #${report.sessionId})",
            report = report,
            entries = entries,
            rawFiles = rawFiles
        )
    }

    private fun resolveFileName(context: Context, uri: Uri): String? {
        return try {
            context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
                if (c.moveToFirst()) c.getString(0) else null
            } ?: uri.lastPathSegment
        } catch (_: Exception) {
            uri.lastPathSegment
        }
    }
}
