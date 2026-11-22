package com.example.engine

import android.content.Context
import android.util.Log
import com.example.i18n.AppLanguage
import com.example.i18n.stringsFor
import com.example.model.ComparisonResult
import com.example.model.FodDiagnosticReport
import com.example.model.PortAnalysisResult
import com.example.model.RawZipArchiveBundle
import com.example.storage.SettingsDataStore
import com.google.firebase.Firebase
import com.google.firebase.FirebaseApp
import com.google.firebase.ai.ai
import com.google.firebase.ai.type.GenerativeBackend
import com.google.firebase.ai.type.ThinkingLevel
import com.google.firebase.ai.type.generationConfig
import com.google.firebase.ai.type.thinkingConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

private const val TAG = "GeminiFodAiAnalyzer"
private const val GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta"
private const val SINGLE_PASS_PROMPT_BUDGET = 85_000

data class AiConnectionTestResult(
    val success: Boolean,
    val providerName: String,
    val detail: String
)

class GeminiFodAiAnalyzer(private val context: Context) {

    private val settingsStore = SettingsDataStore(context)

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

    suspend fun getSavedPersonalApiKey(): String {
        return runCatching { settingsStore.settingsFlow.first().personalGeminiApiKey.trim() }.getOrDefault("")
    }

    suspend fun testAiConnection(
        apiKeyOverride: String? = null,
        language: AppLanguage = AppLanguage.FR
    ): AiConnectionTestResult = withContext(Dispatchers.IO) {
        val personalKey = (apiKeyOverride ?: getSavedPersonalApiKey()).trim()
        var firebaseFailureReason = ""

        if (isFirebaseInitialized()) {
            try {
                val pingReply = withTimeout(25_000L) {
                    val sb = StringBuilder()
                    model.generateContentStream("Reply with exactly: OK").collect { chunk ->
                        sb.append(chunk.text.orEmpty())
                    }
                    sb.toString().trim()
                }
                if (pingReply.isNotEmpty()) {
                    return@withContext AiConnectionTestResult(
                        success = true,
                        providerName = "Firebase AI Logic (gemini-4-carbon)",
                        detail = if (language == AppLanguage.FR) {
                            "Connexion Firebase AI Logic opérationnelle ($pingReply)."
                        } else {
                            "Firebase AI Logic active ($pingReply)."
                        }
                    )
                }
            } catch (e: Exception) {
                firebaseFailureReason = e.localizedMessage ?: e.javaClass.simpleName
                Log.w(TAG, "Firebase AI ping failed: $firebaseFailureReason")
            }
        } else {
            firebaseFailureReason = if (language == AppLanguage.FR) {
                "google-services.json absent (Build CI standalone)"
            } else {
                "google-services.json missing (standalone CI build)"
            }
        }

        if (personalKey.isNotBlank()) {
            return@withContext try {
                val selectedModel = discoverBestGeminiModel(personalKey)
                val reply = generateSinglePersonalTurn(
                    apiKey = personalKey,
                    modelId = selectedModel,
                    prompt = "Reply with exactly: OK"
                )
                AiConnectionTestResult(
                    success = true,
                    providerName = "Gemini API Key ($selectedModel)",
                    detail = if (language == AppLanguage.FR) {
                        "Clé API personnelle fonctionnelle via $selectedModel ($reply)."
                    } else {
                        "Personal Gemini API key verified via $selectedModel ($reply)."
                    }
                )
            } catch (e: Exception) {
                AiConnectionTestResult(
                    success = false,
                    providerName = "Gemini API Key",
                    detail = (e.localizedMessage ?: "API request failed") +
                        if (firebaseFailureReason.isNotBlank()) " | Firebase: $firebaseFailureReason" else ""
                )
            }
        }

        AiConnectionTestResult(
            success = false,
            providerName = if (language == AppLanguage.FR) "Repli forensique local uniquement" else "Local forensic fallback only",
            detail = if (language == AppLanguage.FR) {
                "Firebase indisponible ($firebaseFailureReason) et aucune clé API Gemini personnelle renseignée. Le moteur local déterministe reste actif."
            } else {
                "Firebase unavailable ($firebaseFailureReason) and no personal Gemini API key configured. Deterministic local engine remains active."
            }
        )
    }

    fun synthesizeDiagnosticStream(
        report: FodDiagnosticReport,
        language: AppLanguage
    ): Flow<String> = flow {
        val prompt = buildDiagnosticPrompt(report, language)
        var delivered = false

        // Layer 1: Firebase AI Logic (gemini-4-carbon, Thinking HIGH)
        if (isFirebaseInitialized()) {
            val acc = StringBuilder()
            try {
                withTimeout(65_000L) {
                    model.generateContentStream(prompt).collect { chunk ->
                        val text = chunk.text.orEmpty()
                        if (text.isNotEmpty()) {
                            acc.append(text)
                            emit(acc.toString())
                        }
                    }
                }
                if (acc.isNotEmpty()) delivered = true
            } catch (e: Exception) {
                Log.w(TAG, "Firebase diagnostic AI failed, trying Layer 2 fallback: ${e.message}")
            }
        }

        // Layer 2: Personal Gemini API key via REST SSE
        if (!delivered) {
            val personalKey = getSavedPersonalApiKey()
            if (personalKey.isNotBlank()) {
                try {
                    val acc = StringBuilder()
                    val selectedModel = discoverBestGeminiModel(personalKey)
                    streamViaPersonalApiKey(personalKey, selectedModel, prompt).collect { chunk ->
                        acc.append(chunk)
                        emit(acc.toString())
                    }
                    if (acc.isNotEmpty()) delivered = true
                } catch (e: Exception) {
                    Log.w(TAG, "Personal Gemini key diagnostic AI failed, falling back to local: ${e.message}")
                }
            }
        }

        // Layer 3: Deterministic Local Forensic Synthesis (zero external dependency)
        if (!delivered) {
            emit(buildLocalForensicDiagnosticSynthesis(report, language))
        }
    }.flowOn(Dispatchers.IO)

    fun synthesizeComparisonStream(
        comparison: ComparisonResult,
        rom: FodDiagnosticReport,
        gsi: FodDiagnosticReport,
        language: AppLanguage
    ): Flow<String> = flow {
        val prompt = buildComparisonPrompt(comparison, rom, gsi, language)
        var delivered = false

        if (isFirebaseInitialized()) {
            val acc = StringBuilder()
            try {
                withTimeout(65_000L) {
                    model.generateContentStream(prompt).collect { chunk ->
                        val text = chunk.text.orEmpty()
                        if (text.isNotEmpty()) {
                            acc.append(text)
                            emit(acc.toString())
                        }
                    }
                }
                if (acc.isNotEmpty()) delivered = true
            } catch (e: Exception) {
                Log.w(TAG, "Firebase comparison AI failed, trying Layer 2 fallback: ${e.message}")
            }
        }

        if (!delivered) {
            val personalKey = getSavedPersonalApiKey()
            if (personalKey.isNotBlank()) {
                try {
                    val acc = StringBuilder()
                    val selectedModel = discoverBestGeminiModel(personalKey)
                    streamViaPersonalApiKey(personalKey, selectedModel, prompt).collect { chunk ->
                        acc.append(chunk)
                        emit(acc.toString())
                    }
                    if (acc.isNotEmpty()) delivered = true
                } catch (e: Exception) {
                    Log.w(TAG, "Personal Gemini key comparison AI failed, falling back to local: ${e.message}")
                }
            }
        }

        if (!delivered) {
            emit(buildLocalForensicComparisonSynthesis(comparison, rom, gsi, language))
        }
    }.flowOn(Dispatchers.IO)

    /**
     * Deep 100% factual AI analysis reading EVERY file entry across both ROM & GSI ZIP archives.
     * Emits Pairs of (providerName, accumulatedMarkdownText).
     */
    fun synthesizePortAnalysisStream(
        portResult: PortAnalysisResult,
        romZip: RawZipArchiveBundle,
        gsiZip: RawZipArchiveBundle,
        language: AppLanguage
    ): Flow<Pair<String, String>> = flow {
        val personalKey = getSavedPersonalApiKey()
        val firebaseReady = isFirebaseInitialized()

        // Try Layer 1 (Firebase AI Logic) first, then Layer 2 (Personal Gemini API Key)
        var delivered = false

        if (firebaseReady) {
            try {
                val digestIfNeeded = buildMultiChunkDigestIfOversized(
                    romZip = romZip,
                    gsiZip = gsiZip,
                    language = language,
                    summarizeFn = { chunkPrompt ->
                        val sb = StringBuilder()
                        withTimeout(45_000L) {
                            model.generateContentStream(chunkPrompt).collect { c -> sb.append(c.text.orEmpty()) }
                        }
                        sb.toString()
                    }
                )
                val prompt = buildPortMasterPrompt(portResult, romZip, gsiZip, digestIfNeeded, language)
                val provider = "Firebase AI Logic (gemini-4-carbon · High Thinking)"
                val acc = StringBuilder()
                withTimeout(90_000L) {
                    model.generateContentStream(prompt).collect { chunk ->
                        val text = chunk.text.orEmpty()
                        if (text.isNotEmpty()) {
                            acc.append(text)
                            emit(provider to acc.toString())
                        }
                    }
                }
                if (acc.isNotEmpty()) delivered = true
            } catch (e: Exception) {
                Log.w(TAG, "Firebase PORT AI failed, trying personal API key if present: ${e.message}")
            }
        }

        if (!delivered && personalKey.isNotBlank()) {
            try {
                val modelId = discoverBestGeminiModel(personalKey)
                val provider = "Gemini API Key ($modelId)"
                val digestIfNeeded = buildMultiChunkDigestIfOversized(
                    romZip = romZip,
                    gsiZip = gsiZip,
                    language = language,
                    summarizeFn = { chunkPrompt ->
                        generateSinglePersonalTurn(personalKey, modelId, chunkPrompt)
                    }
                )
                val prompt = buildPortMasterPrompt(portResult, romZip, gsiZip, digestIfNeeded, language)
                val acc = StringBuilder()
                streamViaPersonalApiKey(personalKey, modelId, prompt).collect { chunk ->
                    acc.append(chunk)
                    emit(provider to acc.toString())
                }
                if (acc.isNotEmpty()) delivered = true
            } catch (e: Exception) {
                Log.w(TAG, "Personal Gemini key PORT AI failed, falling back to local synthesis: ${e.message}")
            }
        }

        if (!delivered) {
            val provider = if (language == AppLanguage.FR) {
                "Moteur Forensique Local (100 % Factuel)"
            } else {
                "Local Forensic Engine (100% Factual)"
            }
            emit(provider to buildLocalForensicPortSynthesis(portResult, romZip, gsiZip, language))
        }
    }.flowOn(Dispatchers.IO)

    // -------------------------------------------------------------------------
    // Layer 2: Gemini Developer REST SSE Client (no new external dependencies)
    // -------------------------------------------------------------------------

    internal suspend fun discoverBestGeminiModel(apiKey: String): String = withContext(Dispatchers.IO) {
        val url = URL("$GEMINI_API_BASE/models?pageSize=100&key=${URLEncoder.encode(apiKey, "UTF-8")}")
        val conn = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 15_000
            readTimeout = 20_000
        }
        try {
            val code = conn.responseCode
            val bodyStream = if (code in 200..299) conn.inputStream else conn.errorStream
            val body = bodyStream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
            if (code !in 200..299) {
                throw IllegalStateException(extractApiErrorMessage(code, body))
            }
            val root = JSONObject(body)
            val models = root.optJSONArray("models") ?: JSONArray()
            val candidates = mutableListOf<String>()
            for (i in 0 until models.length()) {
                val obj = models.optJSONObject(i) ?: continue
                val fullName = obj.optString("name", "") // "models/gemini-2.5-pro"
                val shortName = fullName.removePrefix("models/")
                val methods = obj.optJSONArray("supportedGenerationMethods") ?: JSONArray()
                var supportsGenerate = false
                for (j in 0 until methods.length()) {
                    if (methods.optString(j) == "generateContent") {
                        supportsGenerate = true
                        break
                    }
                }
                if (supportsGenerate &&
                    shortName.startsWith("gemini-", ignoreCase = true) &&
                    !shortName.contains("embedding", true) &&
                    !shortName.contains("tts", true) &&
                    !shortName.contains("image", true) &&
                    !shortName.contains("aqa", true) &&
                    !shortName.contains("robotics", true)
                ) {
                    candidates += shortName
                }
            }
            val preferredPrefixes = listOf(
                "gemini-4",
                "gemini-3",
                "gemini-2.5-pro",
                "gemini-2.5-flash",
                "gemini-2.0-flash"
            )
            for (prefix in preferredPrefixes) {
                val match = candidates.firstOrNull {
                    it.contains(prefix, ignoreCase = true) && !it.contains("lite", ignoreCase = true)
                } ?: candidates.firstOrNull { it.contains(prefix, ignoreCase = true) }
                if (match != null) return@withContext match
            }
            return@withContext candidates.firstOrNull() ?: "gemini-2.5-flash"
        } finally {
            conn.disconnect()
        }
    }

    private suspend fun generateSinglePersonalTurn(
        apiKey: String,
        modelId: String,
        prompt: String
    ): String = withContext(Dispatchers.IO) {
        val sb = StringBuilder()
        streamViaPersonalApiKey(apiKey, modelId, prompt).collect { sb.append(it) }
        sb.toString()
    }

    private fun streamViaPersonalApiKey(
        apiKey: String,
        modelId: String,
        prompt: String
    ): Flow<String> = flow {
        val encodedKey = URLEncoder.encode(apiKey, "UTF-8")
        val encodedModel = URLEncoder.encode(modelId, "UTF-8")
        val endpoint = "$GEMINI_API_BASE/models/$encodedModel:streamGenerateContent?alt=sse&key=$encodedKey"

        // Try with HIGH thinking first; if HTTP 400 because model rejects thinkingLevel, retry without thinkingConfig
        val tryThink = executeSseRequest(endpoint, prompt, includeThinkingConfig = true)
        if (tryThink.isSuccess) {
            tryThink.getOrThrow().forEach { chunk -> emit(chunk) }
            return@flow
        }
        val err = tryThink.exceptionOrNull()
        if (err is HttpBadRequestException) {
            val retryPlain = executeSseRequest(endpoint, prompt, includeThinkingConfig = false)
            retryPlain.getOrThrow().forEach { chunk -> emit(chunk) }
        } else if (err != null) {
            throw err
        }
    }

    private class HttpBadRequestException(message: String) : IllegalStateException(message)

    private fun executeSseRequest(
        endpoint: String,
        prompt: String,
        includeThinkingConfig: Boolean
    ): Result<List<String>> {
        val conn = (URL(endpoint).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = true
            connectTimeout = 20_000
            readTimeout = 90_000
            setRequestProperty("Content-Type", "application/json; charset=UTF-8")
            setRequestProperty("Accept", "text/event-stream")
        }
        return try {
            val payload = JSONObject().apply {
                put("contents", JSONArray().apply {
                    put(JSONObject().apply {
                        put("role", "user")
                        put("parts", JSONArray().apply {
                            put(JSONObject().put("text", prompt))
                        })
                    })
                })
                if (includeThinkingConfig) {
                    put("generationConfig", JSONObject().apply {
                        put("thinkingConfig", JSONObject().apply {
                            put("thinkingLevel", "HIGH")
                        })
                    })
                }
            }.toString()

            OutputStreamWriter(conn.outputStream, Charsets.UTF_8).use { writer ->
                writer.write(payload)
                writer.flush()
            }

            val code = conn.responseCode
            if (code == 400) {
                val errBody = conn.errorStream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
                return Result.failure(HttpBadRequestException(extractApiErrorMessage(code, errBody)))
            }
            if (code !in 200..299) {
                val errBody = conn.errorStream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
                return Result.failure(IllegalStateException(extractApiErrorMessage(code, errBody)))
            }

            val chunks = mutableListOf<String>()
            BufferedReader(InputStreamReader(conn.inputStream, Charsets.UTF_8)).use { reader ->
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    val trimmed = line.orEmpty().trim()
                    if (!trimmed.startsWith("data:")) continue
                    val jsonStr = trimmed.removePrefix("data:").trim()
                    if (jsonStr.isEmpty() || jsonStr == "[DONE]") continue
                    val text = parseSseChunkText(jsonStr)
                    if (text.isNotEmpty()) chunks += text
                }
            }
            Result.success(chunks)
        } catch (e: Exception) {
            Result.failure(e)
        } finally {
            conn.disconnect()
        }
    }

    internal fun parseSseChunkText(jsonStr: String): String {
        return runCatching {
            val obj = JSONObject(jsonStr)
            val candidates = obj.optJSONArray("candidates") ?: return@runCatching ""
            val first = candidates.optJSONObject(0) ?: return@runCatching ""
            val content = first.optJSONObject("content") ?: return@runCatching ""
            val parts = content.optJSONArray("parts") ?: return@runCatching ""
            buildString {
                for (i in 0 until parts.length()) {
                    val part = parts.optJSONObject(i) ?: continue
                    if (part.optBoolean("thought", false)) continue
                    append(part.optString("text", ""))
                }
            }
        }.getOrDefault("")
    }

    private fun extractApiErrorMessage(code: Int, body: String): String {
        val parsed = runCatching {
            JSONObject(body).optJSONObject("error")?.optString("message").orEmpty()
        }.getOrDefault("")
        return if (parsed.isNotBlank()) "HTTP $code: $parsed" else "HTTP $code: ${body.take(240)}"
    }

    // -------------------------------------------------------------------------
    // Multi-chunk full-ZIP reading helper + 100% factual PORT prompt builder
    // -------------------------------------------------------------------------

    private suspend fun buildMultiChunkDigestIfOversized(
        romZip: RawZipArchiveBundle,
        gsiZip: RawZipArchiveBundle,
        language: AppLanguage,
        summarizeFn: suspend (String) -> String
    ): String {
        val allRawCombinedSize = romZip.rawFiles.values.sumOf { it.length } + gsiZip.rawFiles.values.sumOf { it.length }
        if (allRawCombinedSize <= SINGLE_PASS_PROMPT_BUDGET) {
            return buildFullArchiveFilesBlock(romZip, gsiZip, maxPerFileChars = 12_000)
        }

        // Oversized archives: batch EVERY file in both ZIPs into chunks so nothing is skipped!
        val langNote = if (language == AppLanguage.FR) "Français technique concis." else "Concise technical English."
        val allFilePairs = (romZip.entries.map { "ROM" to it.path } + gsiZip.entries.map { "GSI" to it.path })
            .filterNot { it.second == "report.json" || it.second == "REPORT_FULL.md" }

        val batches = mutableListOf<String>()
        val currentBatch = StringBuilder()
        for ((side, path) in allFilePairs) {
            val body = (if (side == "ROM") romZip.rawFiles[path] else gsiZip.rawFiles[path]).orEmpty()
            if (body.isBlank()) continue
            val block = "\n=== [$side] $path (${body.length} chars) ===\n${body.take(18_000)}\n"
            if (currentBatch.length + block.length > 36_000 && currentBatch.isNotEmpty()) {
                batches += currentBatch.toString()
                currentBatch.clear()
            }
            currentBatch.append(block)
        }
        if (currentBatch.isNotEmpty()) batches += currentBatch.toString()

        val digestedParts = mutableListOf<String>()
        batches.take(5).forEachIndexed { idx, batchContent ->
            val prompt = """
                $langNote
                Extract 100% FACTUAL FOD/UDFPS/Biometric/Display/HBM/SELinux/HAL/Overlay/Property facts from batch ${idx + 1}/${minOf(batches.size, 5)}.
                Cite EXACT filenames, keys, package names, sysfs paths, and log lines only. Zero speculation.
                $batchContent
            """.trimIndent()
            val summary = runCatching { summarizeFn(prompt) }.getOrDefault("")
            if (summary.isNotBlank()) {
                digestedParts += "--- BATCH ${idx + 1} FACTUAL DIGEST ---\n$summary"
            }
        }
        return if (digestedParts.isNotEmpty()) {
            digestedParts.joinToString("\n\n") + "\n\n" + buildFullArchiveFilesBlock(romZip, gsiZip, maxPerFileChars = 3_000)
        } else {
            buildFullArchiveFilesBlock(romZip, gsiZip, maxPerFileChars = 5_000)
        }
    }

    private fun buildFullArchiveFilesBlock(
        romZip: RawZipArchiveBundle,
        gsiZip: RawZipArchiveBundle,
        maxPerFileChars: Int
    ): String = buildString {
        val priorityPaths = (romZip.entries.map { it.path } + gsiZip.entries.map { it.path })
            .distinct()
            .filterNot { it == "report.json" || it == "REPORT_FULL.md" }

        for (path in priorityPaths) {
            val rText = romZip.rawFiles[path]
            val gText = gsiZip.rawFiles[path]
            appendLine("=== ZIP ENTRY: $path ===")
            if (rText != null) {
                appendLine("[ROM ($path, ${rText.length} chars)]")
                appendLine(rText.take(maxPerFileChars))
            } else {
                appendLine("[ROM ($path): ABSENT]")
            }
            if (gText != null) {
                appendLine("[GSI ($path, ${gText.length} chars)]")
                appendLine(gText.take(maxPerFileChars))
            } else {
                appendLine("[GSI ($path): ABSENT]")
            }
            appendLine()
        }
    }

    private fun buildPortMasterPrompt(
        portResult: PortAnalysisResult,
        romZip: RawZipArchiveBundle,
        gsiZip: RawZipArchiveBundle,
        allFilesContentBlock: String,
        language: AppLanguage
    ): String {
        val langInstr = if (language == AppLanguage.FR) {
            "Réponds exclusivement en français technique structuré, clair et actionnable."
        } else {
            "Respond exclusively in structured, clear, actionable technical English."
        }

        val manifestRom = romZip.entries.joinToString("\n") { "  - ${it.path} (${it.sizeBytes} B, ${it.lineCount} lines)" }
        val manifestGsi = gsiZip.entries.joinToString("\n") { "  - ${it.path} (${it.sizeBytes} B, ${it.lineCount} lines)" }
        val diffsDump = portResult.factualDiffs.take(90).joinToString("\n") { d ->
            "- [${d.status}] (${d.sourceFile}) ${d.category} :: ${d.title}\n  ROM: ${d.romEvidence.replace("\n", " | ")}\n  GSI: ${d.gsiEvidence.replace("\n", " | ")}\n  Impact: ${d.impact}"
        }
        val noiseDump = portResult.sharedNoiseSamples.take(25).joinToString("\n") { n ->
            "- (${n.sourceFile}) ${n.title}: ${n.impact}"
        }
        val tiersDump = portResult.portingSolutions.joinToString("\n") { s ->
            "- Rank ${s.rank} [${s.confidencePercent}% | SystemUI/FW=${s.requiresFrameworkOrSystemUi}] ${s.title}: ${s.whyItApplies}"
        }
        val extractablesDump = if (portResult.extractableFiles.isEmpty()) {
            "(No resolved extractable file provenance entries)"
        } else {
            portResult.extractableFiles.joinToString("\n") { ex ->
                "- [${ex.category} | ${ex.priorityPercent}%] ${ex.title}\n  ROM File: ${ex.romFilePath} (Dir: ${ex.romDirectory})\n  Target GSI: ${ex.targetGsiPath}\n  Missing Mechanism: ${ex.missingMechanism}\n  Important Contents: ${ex.importantElements.take(10).joinToString(" | ")}"
            }
        }

        return """
            $langInstr
            You are a Principal Android GSI / Treble FOD Reverse Engineer.
            TASK: Produce a 100% FACTUAL root-cause explanation, EXACT FILE EXTRACTION LIST (exact partition paths, directories & key internal contents), and exact SYSTEM-SIDE PORTING BLUEPRINT explaining why GSI FOD breaks (e.g., light turns on, zero enroll/error) while Custom ROM works cleanly.

            STRICT GROUNDING RULES (100% FACTUAL):
            1. Cite ONLY exact filenames inside the two ZIPs AND exact Android partition paths/directories from raw/overlay_deep_inspect.txt, raw/file_provenance_index.txt, raw/proc_live_maps.txt, and raw/dex_source_extract.txt (e.g. /product/overlay/..., /system_ext/priv-app/..., /product/etc/displayconfig/..., /vendor/etc/init/...), exact ARSC keys/values, decoded DEX classes/methods, and exact log lines observed below.
            2. Reject unrelated generic UI overlays that have zero decoded FOD/UDFPS/Biometric keys in resources.arsc / lookupWinners (never fixate on package name alone). Highlight only overlays and DEX/ELF binaries backed by decoded content or live /proc/<pid>/maps.
            3. ARCHITECTURAL INVARIANT: BOTH ROM and GSI share the EXACT SAME UNTOUCHED `boot` and `vendor` partitions. NEVER propose editing /vendor, vendor HAL binaries, or boot/kernel. Only recommend GSI/system-side solutions (props/PHH -> RRO overlays / system init / system sepolicy -> SystemUI UdfpsController / HBM -> Framework BiometricService / HAL extension).
            4. Filter out noise: Ignore DisplayBrightness floats, StablePhysical display addresses, Cutouts, build dates, and anything missing/failing identically on BOTH ROM and GSI (or INACTIVE `[ ]` on ROM). Explicitly reject false leads.
            5. Conclude with a ranked recommendation ("MEILLEURE SOLUTION DE PORTAGE") with step-by-step concrete extraction/porting commands on the GSI.
            6. Label statements with [FACT], [CORRELATION], or [DEDUCTION]. Zero hallucination.

            VERDICT PRELIMINARY: ${portResult.factualRootCauseVerdict}
            BOOT/VENDOR PARITY: ${portResult.bootVendorParityVerified} -> ${portResult.bootVendorParitySummary}

            EXACT FILES & MECHANISMS TO EXTRACT FROM CUSTOM ROM (${portResult.extractableFiles.size}):
            $extractablesDump

            COMPLETE ROM ZIP INDEX (${romZip.totalFiles} files, ${romZip.totalBytes} B):
            $manifestRom

            COMPLETE GSI ZIP INDEX (${gsiZip.totalFiles} files, ${gsiZip.totalBytes} B):
            $manifestGsi

            ALL COMPUTED FACTUAL DIFFS (${portResult.factualDiffs.size}):
            $diffsDump

            FILTERED SHARED NON-BLOCKING NOISE (${portResult.filteredSharedNoiseCount} total):
            $noiseDump

            PRE-RANKED PORTING TIERS:
            $tiersDump

            COMPLETE CONTENTS OF BOTH ZIP ARCHIVES:
            $allFilesContentBlock
        """.trimIndent()
    }

    internal fun buildLocalForensicPortSynthesis(
        portResult: PortAnalysisResult,
        romZip: RawZipArchiveBundle,
        gsiZip: RawZipArchiveBundle,
        language: AppLanguage
    ): String {
        val notice = stringsFor(language).aiLocalFallbackNotice
        val topSol = portResult.portingSolutions.maxByOrNull { it.confidencePercent } ?: portResult.portingSolutions.firstOrNull()
        val failedDiffs = portResult.factualDiffs.filter { it.status == com.example.model.EvidenceStatus.FAILED }
        val otherDiffs = portResult.factualDiffs.filter { it.status != com.example.model.EvidenceStatus.FAILED }

        return buildString {
            appendLine(notice)
            appendLine()
            appendLine("### [FACT] ${if (language == AppLanguage.FR) "Inventaire intégral lu dans les 2 ZIP" else "Exhaustive Inventory Read From Both ZIPs"}")
            appendLine("- ROM ZIP: `${romZip.sourceName}` (${romZip.totalFiles} fichiers, ${romZip.totalBytes / 1024} Ko)")
            appendLine("- GSI ZIP: `${gsiZip.sourceName}` (${gsiZip.totalFiles} fichiers, ${gsiZip.totalBytes / 1024} Ko)")
            appendLine("- Boot/Vendor Parity: `${portResult.bootVendorParityVerified}` — ${portResult.bootVendorParitySummary}")
            appendLine()
            appendLine("### [FACT] ${if (language == AppLanguage.FR) "Causes réelles détectées dans les fichiers bruts (${failedDiffs.size} critiques)" else "Actual Root Causes Found in Raw Files (${failedDiffs.size} critical)"}")
            if (failedDiffs.isEmpty() && otherDiffs.isEmpty()) {
                appendLine(if (language == AppLanguage.FR) "- Aucune divergence FOD critique détectée dans les fichiers texte des deux ZIP." else "- No critical FOD divergence found in the two ZIP text artifacts.")
            } else {
                (failedDiffs + otherDiffs).take(20).forEach { d ->
                    appendLine("- **[${d.status}] (${d.sourceFile}) ${d.title}**")
                    appendLine("  - ROM: ${d.romEvidence.replace("\n", " | ")}")
                    appendLine("  - GSI: ${d.gsiEvidence.replace("\n", " | ")}")
                    appendLine("  - Impact: ${d.impact}")
                }
            }
            appendLine()
            if (portResult.extractableFiles.isNotEmpty()) {
                appendLine("### [FACT] ${if (language == AppLanguage.FR) "Fichiers & mécanismes exacts à extraire du Custom ROM (${portResult.extractableFiles.size})" else "Exact Files & Mechanisms to Extract From Custom ROM (${portResult.extractableFiles.size})"}")
                portResult.extractableFiles.take(15).forEach { ex ->
                    appendLine("- **[${ex.category} · ${ex.priorityPercent}%] ${ex.title}**")
                    appendLine("  - ${if (language == AppLanguage.FR) "Fichier ROM" else "ROM File"}: `${ex.romFilePath}` (${if (language == AppLanguage.FR) "Répertoire" else "Directory"}: `${ex.romDirectory}`)")
                    appendLine("  - ${if (language == AppLanguage.FR) "Destination GSI" else "GSI Target"}: `${ex.targetGsiPath}`")
                    appendLine("  - ${if (language == AppLanguage.FR) "Mécanisme" else "Mechanism"}: ${ex.missingMechanism}")
                    ex.importantElements.take(6).forEach { el -> appendLine("    - `$el`") }
                }
                appendLine()
            }
            appendLine("### [DEDUCTION] ${if (language == AppLanguage.FR) "Bruit partagé écarté" else "Filtered Shared Noise"} (${portResult.filteredSharedNoiseCount})")
            portResult.sharedNoiseSamples.take(6).forEach { s ->
                appendLine("- (${s.sourceFile}) ${s.title}: ${s.impact}")
            }
            appendLine()
            appendLine("### [DEDUCTION] ${if (language == AppLanguage.FR) "Meilleure solution de portage côté GSI (boot & vendor intacts)" else "Best GSI-Side Porting Strategy (boot & vendor untouched)"}")
            if (topSol != null) {
                appendLine("- **${topSol.title}** (${topSol.confidencePercent}% confiance · ${topSol.layer})")
                topSol.concreteActionSteps.forEach { step -> appendLine("  1. $step") }
            }
            portResult.portingSolutions.filter { it.id != topSol?.id }.forEach { sol ->
                appendLine("- Alternative (${sol.confidencePercent}%): **${sol.title}** — ${sol.whyItApplies}")
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
            if (report.procLiveMaps.isNotEmpty()) {
                appendLine()
                appendLine("### [FACT] ${if (language == AppLanguage.FR) "Processus FOD live (/proc/<pid>/maps & fd)" else "Live FOD Processes (/proc/<pid>/maps & fd)"}")
                report.procLiveMaps.take(8).forEach { rec ->
                    appendLine("  - `${rec.processName}` (pid=${rec.pid}): matchedFod=${rec.matchedFodPaths.take(4)} | newMaps=${rec.enrollmentNewMappedFiles.size} | newFds=${rec.enrollmentNewFds.size}")
                }
            }
            if (report.dexSourceExtracts.isNotEmpty()) {
                appendLine()
                appendLine("### [FACT] ${if (language == AppLanguage.FR) "Code source DEX extrait (Classes & Méthodes)" else "Extracted DEX Source (Classes & Methods)"}")
                report.dexSourceExtracts.take(6).forEach { dex ->
                    appendLine("  - `${dex.archivePath}` (${dex.targetHint}): ${dex.matchedClasses.size} classes, ${dex.matchedMethods.size} methods → ${dex.matchedClasses.take(4).joinToString(", ")}")
                }
            }
            val topRros = report.overlayInspections.filter { it.fodRelevanceScore >= 30 || it.lookupWinners.isNotEmpty() }
            if (topRros.isNotEmpty()) {
                appendLine()
                appendLine("### [FACT] ${if (language == AppLanguage.FR) "Overlays RRO FOD prouvés par contenu ARSC/Lookup" else "Content-Proven FOD RRO Overlays"}")
                topRros.take(8).forEach { ov ->
                    appendLine("  - `${ov.packageName}` (score=${ov.fodRelevanceScore}, live=${ov.provenInLiveMaps}, apk=`${ov.apkPath}`): ${(ov.lookupWinners + ov.decodedArscEntries).take(4).joinToString(" ; ")}")
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

            DEEP OVERLAY INSPECTIONS (${report.overlayInspections.size}):
            ${report.rawArtifacts.overlayDeepInspect.take(5500)}

            LIVE /proc/<pid>/maps & fd (${report.procLiveMaps.size} processes):
            ${report.rawArtifacts.procLiveMaps.take(4500)}

            DEX SOURCE-LEVEL EXTRACTS (${report.dexSourceExtracts.size} archives):
            ${report.rawArtifacts.dexSourceExtract.take(4500)}

            DYNAMIC FILE PROVENANCE INDEX (${report.fileProvenance.size}):
            ${report.rawArtifacts.fileProvenanceIndex.take(4500)}

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
