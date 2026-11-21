package com.example.viewmodel

import android.app.Application
import android.net.Uri
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.engine.FodComparatorEngine
import com.example.engine.GeminiFodAiAnalyzer
import com.example.i18n.AppLanguage
import com.example.model.ComparisonResult
import com.example.model.DiagnosticMode
import com.example.model.FodDiagnosticReport
import com.example.storage.LocalSessionRepository
import com.example.storage.StreamingReportExporter
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

private const val TAG = "ComparatorViewModel"

class ComparatorViewModel(application: Application) : AndroidViewModel(application) {

    private val aiAnalyzer = GeminiFodAiAnalyzer()
    private val sessionRepo = LocalSessionRepository(application)

    private val _romReport = MutableStateFlow<FodDiagnosticReport?>(null)
    val romReport: StateFlow<FodDiagnosticReport?> = _romReport.asStateFlow()

    private val _gsiReport = MutableStateFlow<FodDiagnosticReport?>(null)
    val gsiReport: StateFlow<FodDiagnosticReport?> = _gsiReport.asStateFlow()

    private val _comparisonResult = MutableStateFlow<ComparisonResult?>(null)
    val comparisonResult: StateFlow<ComparisonResult?> = _comparisonResult.asStateFlow()

    private val _aiComparisonState = MutableStateFlow<AiSynthesisState>(AiSynthesisState.Idle)
    val aiComparisonState: StateFlow<AiSynthesisState> = _aiComparisonState.asStateFlow()

    private val _importError = MutableStateFlow<String?>(null)
    val importError: StateFlow<String?> = _importError.asStateFlow()

    private val _exportState = MutableStateFlow(ExportBannerState())
    val exportState: StateFlow<ExportBannerState> = _exportState.asStateFlow()

    fun importZip(isRom: Boolean, uri: Uri) {
        viewModelScope.launch {
            _importError.value = null
            try {
                val report = StreamingReportExporter.importReportFromZip(getApplication(), uri)
                if (isRom) {
                    _romReport.value = report
                } else {
                    _gsiReport.value = report
                }
                _comparisonResult.value = null
                _aiComparisonState.value = AiSynthesisState.Idle
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "ZIP import failed", e)
                _importError.value = e.localizedMessage ?: "Failed to parse ZIP archive"
            }
        }
    }

    fun loadLocalSession(isRom: Boolean) {
        viewModelScope.launch {
            val mode = if (isRom) DiagnosticMode.ROM_FOD else DiagnosticMode.GSI_FOD
            val report = sessionRepo.loadLatestReport(mode)
            if (report != null) {
                if (isRom) _romReport.value = report else _gsiReport.value = report
                _importError.value = null
            } else {
                _importError.value = "No local saved ${mode.name} session found."
            }
        }
    }

    fun runComparison(language: AppLanguage) {
        val rom = _romReport.value ?: return
        val gsi = _gsiReport.value ?: return
        val diff = FodComparatorEngine.compare(rom, gsi, language)
        _comparisonResult.value = diff
        runAiComparisonSynthesis(diff, rom, gsi, language)
    }

    fun runAiComparisonSynthesis(
        comparison: ComparisonResult,
        rom: FodDiagnosticReport,
        gsi: FodDiagnosticReport,
        language: AppLanguage
    ) {
        viewModelScope.launch {
            _aiComparisonState.value = AiSynthesisState.Loading
            var finalText = ""
            try {
                aiAnalyzer.synthesizeComparisonStream(comparison, rom, gsi, language).collect { partial ->
                    finalText = partial
                    _aiComparisonState.value = AiSynthesisState.Streaming(partial)
                }
                if (finalText.isBlank()) {
                    _aiComparisonState.value = AiSynthesisState.Error("Gemini returned an empty comparison analysis.")
                } else {
                    _aiComparisonState.value = AiSynthesisState.Success(finalText)
                    _comparisonResult.value = comparison.copy(aiDeepComparisonMarkdown = finalText)
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "Gemini comparison failed", e)
                _aiComparisonState.value = AiSynthesisState.Error(
                    e.localizedMessage ?: "Gemini comparison analysis failed."
                )
            }
        }
    }

    fun exportComparison(asHtml: Boolean, language: AppLanguage, targetUri: Uri?) {
        val comp = _comparisonResult.value ?: return
        val rom = _romReport.value ?: return
        val gsi = _gsiReport.value ?: return
        viewModelScope.launch {
            _exportState.value = ExportBannerState(isExporting = true)
            try {
                val path = StreamingReportExporter.exportComparisonSingleFile(
                    context = getApplication(),
                    comparison = comp,
                    rom = rom,
                    gsi = gsi,
                    language = language,
                    asHtml = asHtml,
                    targetUri = targetUri
                )
                _exportState.value = ExportBannerState(isExporting = false, message = path)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "Comparison export failed", e)
                _exportState.value = ExportBannerState(
                    isExporting = false,
                    message = e.localizedMessage ?: "Export failed",
                    isError = true
                )
            }
        }
    }

    fun clearExportMessage() {
        _exportState.value = ExportBannerState()
    }
}
