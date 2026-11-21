package com.example.storage

import android.content.Context
import com.example.model.DiagnosticMode
import com.example.model.FodDiagnosticReport
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

class LocalSessionRepository(private val context: Context) {

    private val moshi: Moshi = Moshi.Builder()
        .addLast(KotlinJsonAdapterFactory())
        .build()

    private val adapter = moshi.adapter(FodDiagnosticReport::class.java)

    private fun sessionsDir(): File {
        val dir = File(context.filesDir, "fod_sessions")
        if (!dir.exists()) dir.mkdirs()
        return dir
    }

    suspend fun saveLatestReport(report: FodDiagnosticReport) = withContext(Dispatchers.IO) {
        val file = File(sessionsDir(), "latest_${report.mode.name.lowercase()}.json")
        file.writeText(adapter.toJson(report), Charsets.UTF_8)
    }

    suspend fun loadLatestReport(mode: DiagnosticMode): FodDiagnosticReport? = withContext(Dispatchers.IO) {
        val file = File(sessionsDir(), "latest_${mode.name.lowercase()}.json")
        if (!file.exists()) return@withContext null
        try {
            adapter.fromJson(file.readText(Charsets.UTF_8))
        } catch (e: Exception) {
            null
        }
    }
}
