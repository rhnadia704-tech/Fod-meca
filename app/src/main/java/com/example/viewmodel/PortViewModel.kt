package com.example.viewmodel

import android.app.Application
import android.net.Uri
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.engine.GeminiFodAiAnalyzer
import com.example.engine.PortAnalysisEngine
import com.example.engine.PortZipDeepReader
import com.example.i18n.AppLanguage
import com.example.model.DiagnosticMode
import com.example.model.PortAnalysisResult
import com.example.model.RawZipArchiveBundle
import com.example.storage.LocalSessionRepository
import com.example.storage.StreamingReportExporter
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private const val TAG = "PortViewModel"

sealed interface PortPhase {
    data object Idle : PortPhase
    data object ReadingZips : PortPhase
    data object AnalyzingDiffs : PortPhase
    data object RunningAi : PortPhase
    data class Error(val message: String) : PortPhase
}

class PortViewModel(application: Application) : AndroidViewModel(application) {

    private val aiAnalyzer = GeminiFodAiAnalyzer(application)
    private val sessionRepo = LocalSessionRepository(application)

    private val _romArchive = MutableStateFlow<RawZipArchiveBundle?>(null)
    val romArchive: StateFlow<RawZipArchiveBundle?> = _romArchive.asStateFlow()

    private val _gsiArchive = MutableStateFlow<RawZipArchiveBundle?>(null)
    val gsiArchive: StateFlow<RawZipArchiveBundle?> = _gsiArchive.asStateFlow()

    private val _portResult = MutableStateFlow<PortAnalysisResult?>(null)
    val portResult: StateFlow<PortAnalysisResult?> = _portResult.asStateFlow()

    private val _portPhase = MutableStateFlow<PortPhase>(PortPhase.Idle)
    val portPhase: StateFlow<PortPhase> = _portPhase.asStateFlow()

    private val _aiStreamText = MutableStateFlow("")
    val aiStreamText: StateFlow<String> = _aiStreamText.asStateFlow()

    private val _aiProviderLabel = MutableStateFlow("")
    val aiProviderLabel: StateFlow<String> = _aiProviderLabel.asStateFlow()

    private val _importError = MutableStateFlow<String?>(null)
    val importError: StateFlow<String?> = _importError.asStateFlow()

    private val _exportState = MutableStateFlow(ExportBannerState())
    val exportState: StateFlow<ExportBannerState> = _exportState.asStateFlow()

    fun importZip(isRom: Boolean, uri: Uri) {
        viewModelScope.launch {
            _importError.value = null
            _portPhase.value = PortPhase.ReadingZips
            try {
                val bundle = PortZipDeepReader.readCompleteZip(
                    context = getApplication(),
                    uri = uri,
                    archiveLabel = if (isRom) "ROM" else "GSI"
                )
                if (isRom) _romArchive.value = bundle else _gsiArchive.value = bundle
                _portResult.value = null
                _aiStreamText.value = ""
                _aiProviderLabel.value = ""
                _portPhase.value = PortPhase.Idle
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "PORT ZIP deep read failed", e)
                _portPhase.value = PortPhase.Idle
                _importError.value = e.localizedMessage ?: "Failed to read ZIP contents"
            }
        }
    }

    fun loadFromLocalSession(isRom: Boolean) {
        viewModelScope.launch {
            _importError.value = null
            val mode = if (isRom) DiagnosticMode.ROM_FOD else DiagnosticMode.GSI_FOD
            val report = sessionRepo.loadLatestReport(mode)
            if (report == null) {
                _importError.value = "No local saved ${mode.name} session found."
                return@launch
            }
            val bundle = PortZipDeepReader.fromSavedReport(report, if (isRom) "ROM" else "GSI")
            if (isRom) _romArchive.value = bundle else _gsiArchive.value = bundle
            _portResult.value = null
            _aiStreamText.value = ""
            _aiProviderLabel.value = ""
        }
    }

    fun analyzePorting(language: AppLanguage) {
        val rom = _romArchive.value ?: return
        val gsi = _gsiArchive.value ?: return
        viewModelScope.launch {
            _portPhase.value = PortPhase.AnalyzingDiffs
            _aiStreamText.value = ""
            _aiProviderLabel.value = ""
            try {
                val deterministicResult = withContext(Dispatchers.Default) {
                    PortAnalysisEngine.analyze(rom, gsi, language)
                }
                _portResult.value = deterministicResult
                _portPhase.value = PortPhase.RunningAi

                var latestProvider = ""
                var latestText = ""
                aiAnalyzer.synthesizePortAnalysisStream(deterministicResult, rom, gsi, language)
                    .collect { (provider, partialText) ->
                        latestProvider = provider
                        latestText = partialText
                        _aiProviderLabel.value = provider
                        _aiStreamText.value = partialText
                    }

                _portResult.value = deterministicResult.copy(
                    aiProviderUsed = latestProvider,
                    aiFactualSynthesis = latestText
                )
                _portPhase.value = PortPhase.Idle
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "PORT analysis failed", e)
                _portPhase.value = PortPhase.Error(e.localizedMessage ?: "Porting analysis failed")
            }
        }
    }

    fun exportPortReport(asHtml: Boolean, language: AppLanguage, targetUri: Uri?) {
        val result = _portResult.value ?: return
        val rom = _romArchive.value ?: return
        val gsi = _gsiArchive.value ?: return
        viewModelScope.launch {
            _exportState.value = ExportBannerState(isExporting = true)
            try {
                val path = StreamingReportExporter.exportPortSingleFile(
                    context = getApplication(),
                    portResult = result,
                    romZip = rom,
                    gsiZip = gsi,
                    language = language,
                    asHtml = asHtml,
                    targetUri = targetUri
                )
                _exportState.value = ExportBannerState(isExporting = false, message = path)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "PORT export failed", e)
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
