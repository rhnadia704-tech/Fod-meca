package com.example.viewmodel

import android.app.Application
import android.net.Uri
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.engine.BaselineProbeResult
import com.example.engine.ElfDisassembler
import com.example.engine.GeminiFodAiAnalyzer
import com.example.engine.PatchAndArchitectureAnalyzer
import com.example.engine.ShellExecutor
import com.example.engine.SystemProbeCollector
import com.example.i18n.AppLanguage
import com.example.model.DiagnosticMode
import com.example.model.ElfBinaryAnalysis
import com.example.model.FodDiagnosticReport
import com.example.storage.LocalSessionRepository
import com.example.storage.StreamingReportExporter
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

private const val TAG = "DiagnosticViewModel"

sealed interface CapturePhase {
    data object Idle : CapturePhase
    data object ScanningBaseline : CapturePhase
    data class WaitingForEnrollment(
        val elapsedSeconds: Int = 0,
        val observedLiveEvents: Int = 0,
        val rootActive: Boolean = false
    ) : CapturePhase
    data object AnalyzingSession : CapturePhase
    data class Error(val message: String) : CapturePhase
}

sealed interface AiSynthesisState {
    data object Idle : AiSynthesisState
    data object Loading : AiSynthesisState
    data class Streaming(val text: String) : AiSynthesisState
    data class Success(val text: String) : AiSynthesisState
    data class Error(val message: String) : AiSynthesisState
}

enum class ExportKind { ZIP, SINGLE_HTML, SINGLE_MD }

data class ExportBannerState(
    val isExporting: Boolean = false,
    val message: String? = null,
    val isError: Boolean = false
)

class DiagnosticViewModel(application: Application) : AndroidViewModel(application) {

    private val probeCollector = SystemProbeCollector(application)
    private val aiAnalyzer = GeminiFodAiAnalyzer()
    private val sessionRepo = LocalSessionRepository(application)

    private val _selectedMode = MutableStateFlow(DiagnosticMode.ROM_FOD)
    val selectedMode: StateFlow<DiagnosticMode> = _selectedMode.asStateFlow()

    private val _capturePhase = MutableStateFlow<CapturePhase>(CapturePhase.Idle)
    val capturePhase: StateFlow<CapturePhase> = _capturePhase.asStateFlow()

    private val _currentReport = MutableStateFlow<FodDiagnosticReport?>(null)
    val currentReport: StateFlow<FodDiagnosticReport?> = _currentReport.asStateFlow()

    private val _aiState = MutableStateFlow<AiSynthesisState>(AiSynthesisState.Idle)
    val aiState: StateFlow<AiSynthesisState> = _aiState.asStateFlow()

    private val _exportState = MutableStateFlow(ExportBannerState())
    val exportState: StateFlow<ExportBannerState> = _exportState.asStateFlow()

    private var pendingBaseline: BaselineProbeResult? = null
    private var pendingElfs: List<ElfBinaryAnalysis> = emptyList()
    private var enrollmentStartedAtMs: Long = 0L
    private var livePollJob: Job? = null

    init {
        loadSavedSessionForMode(DiagnosticMode.ROM_FOD)
    }

    fun selectMode(mode: DiagnosticMode) {
        _selectedMode.value = mode
        if (_capturePhase.value is CapturePhase.Idle || _capturePhase.value is CapturePhase.Error) {
            loadSavedSessionForMode(mode)
        }
    }

    private fun loadSavedSessionForMode(mode: DiagnosticMode) {
        viewModelScope.launch {
            val saved = sessionRepo.loadLatestReport(mode)
            _currentReport.value = saved
            _aiState.value = if (saved != null && saved.summary.aiThinkingSynthesis.isNotBlank()) {
                AiSynthesisState.Success(saved.summary.aiThinkingSynthesis)
            } else {
                AiSynthesisState.Idle
            }
        }
    }

    fun startBaselineAndWaitForEnrollment(useRoot: Boolean) {
        livePollJob?.cancel()
        viewModelScope.launch {
            _capturePhase.value = CapturePhase.ScanningBaseline
            _aiState.value = AiSynthesisState.Idle
            try {
                val baseline = probeCollector.collectBaseline(useRoot)
                pendingBaseline = baseline

                val effectiveRoot = baseline.environment.rootGranted
                val elfList = mutableListOf<ElfBinaryAnalysis>()
                for (path in baseline.discoveredBinaryPaths.take(18)) {
                    val readRes = ShellExecutor.readBinaryFile(path, effectiveRoot)
                    elfList += ElfDisassembler.analyzeBinary(path, readRes.bytes, readRes.accessError)
                }
                pendingElfs = elfList
                enrollmentStartedAtMs = System.currentTimeMillis()
                _capturePhase.value = CapturePhase.WaitingForEnrollment(
                    elapsedSeconds = 0,
                    observedLiveEvents = 0,
                    rootActive = effectiveRoot
                )

                livePollJob = viewModelScope.launch {
                    var ticks = 0
                    val regex = Regex("(fingerprint|biometric|udfps|fod|hbm|lhbm)", RegexOption.IGNORE_CASE)
                    while (isActive) {
                        delay(1500L)
                        ticks += 2
                        val snapshot = probeCollector.captureLiveEnrollmentLogs(effectiveRoot, durationCheckOnly = true)
                        val count = snapshot.lineSequence().count { regex.containsMatchIn(it) }
                        _capturePhase.value = CapturePhase.WaitingForEnrollment(
                            elapsedSeconds = ((System.currentTimeMillis() - enrollmentStartedAtMs) / 1000L).toInt(),
                            observedLiveEvents = count,
                            rootActive = effectiveRoot
                        )
                    }
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "Baseline scan failed", e)
                _capturePhase.value = CapturePhase.Error(e.localizedMessage ?: "Baseline probe failed")
            }
        }
    }

    fun cancelEnrollmentWait() {
        livePollJob?.cancel()
        pendingBaseline = null
        _capturePhase.value = CapturePhase.Idle
    }

    fun finishEnrollmentAndAnalyze(language: AppLanguage) {
        livePollJob?.cancel()
        val baseline = pendingBaseline ?: run {
            _capturePhase.value = CapturePhase.Error("No active baseline session")
            return
        }

        viewModelScope.launch {
            _capturePhase.value = CapturePhase.AnalyzingSession
            try {
                val duration = maxOf(0L, System.currentTimeMillis() - enrollmentStartedAtMs)
                val liveLogs = probeCollector.captureLiveEnrollmentLogs(
                    useRoot = baseline.environment.rootGranted,
                    durationCheckOnly = false
                )
                val report = PatchAndArchitectureAnalyzer.buildReport(
                    mode = _selectedMode.value,
                    baseline = baseline,
                    liveLogcat = liveLogs,
                    elfAnalyses = pendingElfs,
                    enrollmentDurationMs = duration,
                    language = language
                )
                sessionRepo.saveLatestReport(report)
                _currentReport.value = report
                _capturePhase.value = CapturePhase.Idle
                runAiSynthesis(language)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "Session analysis failed", e)
                _capturePhase.value = CapturePhase.Error(e.localizedMessage ?: "Analysis failed")
            }
        }
    }

    fun runAiSynthesis(language: AppLanguage) {
        val report = _currentReport.value ?: return
        viewModelScope.launch {
            _aiState.value = AiSynthesisState.Loading
            var finalText = ""
            try {
                aiAnalyzer.synthesizeDiagnosticStream(report, language).collect { partial ->
                    finalText = partial
                    _aiState.value = AiSynthesisState.Streaming(partial)
                }
                if (finalText.isBlank()) {
                    _aiState.value = AiSynthesisState.Error("Gemini returned an empty synthesis.")
                } else {
                    _aiState.value = AiSynthesisState.Success(finalText)
                    val updated = report.copy(
                        summary = report.summary.copy(aiThinkingSynthesis = finalText)
                    )
                    _currentReport.value = updated
                    sessionRepo.saveLatestReport(updated)
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "Gemini AI synthesis failed", e)
                _aiState.value = AiSynthesisState.Error(
                    e.localizedMessage ?: "Gemini AI synthesis failed."
                )
            }
        }
    }

    fun exportReport(kind: ExportKind, language: AppLanguage, targetUri: Uri?) {
        val report = _currentReport.value ?: return
        viewModelScope.launch {
            _exportState.value = ExportBannerState(isExporting = true)
            try {
                val ctx = getApplication<Application>()
                val location = when (kind) {
                    ExportKind.ZIP -> StreamingReportExporter.exportDiagnosticZip(ctx, report, language, targetUri)
                    ExportKind.SINGLE_HTML -> StreamingReportExporter.exportDiagnosticSingleFile(ctx, report, language, asHtml = true, targetUri = targetUri)
                    ExportKind.SINGLE_MD -> StreamingReportExporter.exportDiagnosticSingleFile(ctx, report, language, asHtml = false, targetUri = targetUri)
                }
                _exportState.value = ExportBannerState(
                    isExporting = false,
                    message = location,
                    isError = false
                )
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "Export failed", e)
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
