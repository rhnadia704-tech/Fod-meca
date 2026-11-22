package com.example.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.provider.Settings
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Hub
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Timeline
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.i18n.AppLanguage
import com.example.i18n.LocalAppStrings
import com.example.model.DiagnosticMode
import com.example.model.EvidenceStatus
import com.example.model.FodDiagnosticReport
import com.example.ui.components.InteractiveDependencyGraph
import com.example.ui.components.KnowledgeBadge
import com.example.ui.components.StatusPill
import com.example.ui.components.TelemetrySectionCard
import com.example.ui.theme.LocalFodStatusColors
import com.example.viewmodel.AiSynthesisState
import com.example.viewmodel.CapturePhase
import com.example.viewmodel.DiagnosticViewModel
import com.example.viewmodel.ExportKind

@Composable
fun DiagnosticScreen(
    viewModel: DiagnosticViewModel,
    rootEnabled: Boolean,
    allFilesGranted: Boolean,
    language: AppLanguage,
    modifier: Modifier = Modifier
) {
    val strings = LocalAppStrings.current
    val context = LocalContext.current
    val selectedMode by viewModel.selectedMode.collectAsStateWithLifecycle()
    val capturePhase by viewModel.capturePhase.collectAsStateWithLifecycle()
    val currentReport by viewModel.currentReport.collectAsStateWithLifecycle()
    val aiState by viewModel.aiState.collectAsStateWithLifecycle()
    val exportState by viewModel.exportState.collectAsStateWithLifecycle()

    var showExportMenu by remember { mutableStateOf(false) }
    var activeSubTab by rememberSaveable { mutableIntStateOf(0) }
    var componentFilter by rememberSaveable { mutableStateOf("") }
    var statusFilter by rememberSaveable { mutableStateOf<EvidenceStatus?>(null) }

    val zipLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/zip")
    ) { uri ->
        if (uri != null) viewModel.exportReport(ExportKind.ZIP, language, uri)
    }
    val htmlLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("text/html")
    ) { uri ->
        if (uri != null) viewModel.exportReport(ExportKind.SINGLE_HTML, language, uri)
    }
    val mdLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("text/markdown")
    ) { uri ->
        if (uri != null) viewModel.exportReport(ExportKind.SINGLE_MD, language, uri)
    }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        contentPadding = PaddingValues(top = 12.dp, bottom = 28.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    text = strings.appTitle,
                    style = MaterialTheme.typography.displaySmall,
                    color = MaterialTheme.colorScheme.onBackground
                )
                Text(
                    text = strings.appSubtitle,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        // Mode selector: ROM FOD vs GSI FOD
        item {
            Text(
                text = strings.selectModeTitle,
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.primary
            )
            Spacer(Modifier.height(6.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                ModeCard(
                    title = strings.modeRomTitle,
                    description = strings.modeRomDesc,
                    selected = selectedMode == DiagnosticMode.ROM_FOD,
                    onClick = { viewModel.selectMode(DiagnosticMode.ROM_FOD) },
                    modifier = Modifier
                        .weight(1f)
                        .testTag("mode_rom_fod")
                )
                ModeCard(
                    title = strings.modeGsiTitle,
                    description = strings.modeGsiDesc,
                    selected = selectedMode == DiagnosticMode.GSI_FOD,
                    onClick = { viewModel.selectMode(DiagnosticMode.GSI_FOD) },
                    modifier = Modifier
                        .weight(1f)
                        .testTag("mode_gsi_fod")
                )
            }
        }

        // Primary Actions: ANALYSE + EXTRACT RESULTAT
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Button(
                    onClick = { viewModel.startBaselineAndWaitForEnrollment(rootEnabled) },
                    enabled = capturePhase is CapturePhase.Idle || capturePhase is CapturePhase.Error,
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp),
                    modifier = Modifier
                        .weight(1f)
                        .heightIn(min = 50.dp)
                        .testTag("btn_analyse")
                ) {
                    Icon(Icons.Filled.PlayArrow, contentDescription = strings.btnAnalyse, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(5.dp))
                    Text(strings.btnAnalyse, maxLines = 1, softWrap = false)
                }

                Box(modifier = Modifier.weight(1f)) {
                    OutlinedButton(
                        onClick = { showExportMenu = true },
                        enabled = currentReport != null && !exportState.isExporting,
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 50.dp)
                            .testTag("btn_extract_result")
                    ) {
                        Icon(Icons.Filled.Download, contentDescription = strings.btnExtractResult, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(5.dp))
                        Text(
                            text = strings.btnExtractResult,
                            style = MaterialTheme.typography.labelLarge,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                    DropdownMenu(
                        expanded = showExportMenu,
                        onDismissRequest = { showExportMenu = false }
                    ) {
                        val rep = currentReport
                        DropdownMenuItem(
                            text = { Text(strings.btnExportZip) },
                            onClick = {
                                showExportMenu = false
                                if (allFilesGranted) {
                                    viewModel.exportReport(ExportKind.ZIP, language, null)
                                } else {
                                    val name = "fod_${rep?.mode?.name?.lowercase()}_${rep?.sessionId}.zip"
                                    zipLauncher.launch(name)
                                }
                            }
                        )
                        DropdownMenuItem(
                            text = { Text(strings.btnExportSingleHtml) },
                            onClick = {
                                showExportMenu = false
                                if (allFilesGranted) {
                                    viewModel.exportReport(ExportKind.SINGLE_HTML, language, null)
                                } else {
                                    val name = "fod_dossier_${rep?.mode?.name?.lowercase()}_${rep?.sessionId}.html"
                                    htmlLauncher.launch(name)
                                }
                            }
                        )
                        DropdownMenuItem(
                            text = { Text(strings.btnExportSingleMd) },
                            onClick = {
                                showExportMenu = false
                                if (allFilesGranted) {
                                    viewModel.exportReport(ExportKind.SINGLE_MD, language, null)
                                } else {
                                    val name = "fod_dossier_${rep?.mode?.name?.lowercase()}_${rep?.sessionId}.md"
                                    mdLauncher.launch(name)
                                }
                            }
                        )
                    }
                }
            }
        }

        // Export banner feedback
        if (exportState.isExporting || exportState.message != null) {
            item {
                TelemetrySectionCard(
                    borderColor = if (exportState.isError) LocalFodStatusColors.current.failed else LocalFodStatusColors.current.confirmed
                ) {
                    if (exportState.isExporting) {
                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                    } else {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = "${if (exportState.isError) strings.exportErrorMessage else strings.exportSuccessMessage}: ${exportState.message}",
                                style = MaterialTheme.typography.bodySmall,
                                modifier = Modifier.weight(1f)
                            )
                            TextButton(onClick = { viewModel.clearExportMessage() }) {
                                Icon(Icons.Filled.Close, contentDescription = "Dismiss")
                            }
                        }
                    }
                }
            }
        }

        // Active Capture Phase Banner / Guided Enrollment
        when (val phase = capturePhase) {
            is CapturePhase.ScanningBaseline -> {
                item {
                    TelemetrySectionCard(containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.45f)) {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            CircularProgressIndicator(modifier = Modifier.size(22.dp), strokeWidth = 2.5.dp)
                            Text(strings.baselineScanRunning, style = MaterialTheme.typography.titleSmall)
                        }
                    }
                }
            }

            is CapturePhase.WaitingForEnrollment -> {
                item {
                    TelemetrySectionCard(
                        containerColor = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.45f),
                        borderColor = MaterialTheme.colorScheme.secondary
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Box(
                                modifier = Modifier
                                    .size(10.dp)
                                    .clip(CircleShape)
                                    .background(LocalFodStatusColors.current.confirmed)
                            )
                            Text(strings.enrollmentGuideTitle, style = MaterialTheme.typography.titleMedium)
                        }
                        Text(strings.enrollmentGuideBody, style = MaterialTheme.typography.bodyMedium)
                        Text(
                            text = "${strings.capturingLiveLogs} ${phase.elapsedSeconds}s · ${phase.observedLiveEvents} ${strings.eventsCapturedLabel}",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Button(
                                onClick = { openFingerprintEnrollmentSettings(context) },
                                modifier = Modifier
                                    .weight(1f)
                                    .heightIn(min = 48.dp)
                                    .testTag("btn_open_fp_settings")
                            ) {
                                Icon(Icons.Filled.Settings, contentDescription = strings.btnOpenFingerprintSettings)
                                Spacer(Modifier.width(6.dp))
                                Text(strings.btnOpenFingerprintSettings, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            }
                        }
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Button(
                                onClick = { viewModel.finishEnrollmentAndAnalyze(language) },
                                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.secondary),
                                modifier = Modifier
                                    .weight(1f)
                                    .heightIn(min = 48.dp)
                                    .testTag("btn_finish_enrollment")
                            ) {
                                Icon(Icons.Filled.Check, contentDescription = strings.btnFinishAndAnalyze)
                                Spacer(Modifier.width(6.dp))
                                Text(strings.btnFinishAndAnalyze, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            }
                            OutlinedButton(
                                onClick = { viewModel.cancelEnrollmentWait() },
                                modifier = Modifier.heightIn(min = 48.dp)
                            ) {
                                Text(strings.btnCancelCapture)
                            }
                        }
                    }
                }
            }

            is CapturePhase.AnalyzingSession -> {
                item {
                    TelemetrySectionCard {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            CircularProgressIndicator(modifier = Modifier.size(22.dp), strokeWidth = 2.5.dp)
                            Text(strings.deepAnalysisRunning, style = MaterialTheme.typography.titleSmall)
                        }
                    }
                }
            }

            is CapturePhase.Error -> {
                item {
                    TelemetrySectionCard(borderColor = LocalFodStatusColors.current.failed) {
                        Text(phase.message, color = LocalFodStatusColors.current.failed, style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }

            CapturePhase.Idle -> Unit
        }

        // Empty State or FOD LIVE TRACE Dashboard
        val report = currentReport
        if (report == null) {
            item {
                TelemetrySectionCard {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 24.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Fingerprint,
                            contentDescription = strings.emptyDiagnosticTitle,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(48.dp)
                        )
                        Text(strings.emptyDiagnosticTitle, style = MaterialTheme.typography.titleLarge)
                        Text(
                            text = strings.emptyDiagnosticBody,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        } else {
            item {
                DashboardHeaderCard(report = report)
            }

            // Sub-tabs for FOD LIVE TRACE
            item {
                val subTabs = listOf(
                    strings.subTabSessionFlow to Icons.Filled.Timeline,
                    strings.subTabComponents to Icons.Filled.Memory,
                    strings.subTabDependencyGraph to Icons.Filled.Hub,
                    strings.subTabLiveInvestigation to Icons.Filled.Search,
                    strings.subTabSummary to Icons.Filled.VerifiedUser
                )
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    subTabs.forEachIndexed { idx, (label, icon) ->
                        FilterChip(
                            selected = activeSubTab == idx,
                            onClick = { activeSubTab = idx },
                            label = { Text(label, style = MaterialTheme.typography.labelLarge) },
                            leadingIcon = { Icon(icon, contentDescription = label, modifier = Modifier.size(16.dp)) },
                            modifier = Modifier.testTag("dashboard_subtab_$idx")
                        )
                    }
                }
            }

            when (activeSubTab) {
                0 -> { // SESSION FLOW
                    if (report.fingerDownChain.isNotEmpty()) {
                        item {
                            TelemetrySectionCard(borderColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.7f)) {
                                Text(strings.fingerDownChainTitle, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
                                report.fingerDownChain.forEach { step ->
                                    HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Text(step.stage, style = MaterialTheme.typography.labelLarge, modifier = Modifier.weight(1f))
                                        StatusPill(status = step.status)
                                    }
                                    Text(step.detail, style = MaterialTheme.typography.bodySmall)
                                    if (step.evidence.isNotBlank()) {
                                        Text(
                                            text = step.evidence,
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                }
                            }
                        }
                    }
                    if (report.sysfsTransitions.isNotEmpty()) {
                        item {
                            val changedCount = report.sysfsTransitions.count { it.changed }
                            TelemetrySectionCard(
                                borderColor = if (changedCount > 0) LocalFodStatusColors.current.confirmed else LocalFodStatusColors.current.suspect
                            ) {
                                Text("${strings.sysfsTransitionsTitle} ($changedCount/${report.sysfsTransitions.size})", style = MaterialTheme.typography.titleSmall)
                                report.sysfsTransitions.sortedByDescending { it.changed }.take(15).forEach { t ->
                                    val c = if (t.changed) LocalFodStatusColors.current.confirmed else MaterialTheme.colorScheme.onSurfaceVariant
                                    Text(
                                        text = "${if (t.changed) "[CHANGED]" else "[STATIC]"} ${t.nodePath.substringAfterLast('/')}: ${t.beforeValue} → ${if (t.liveValues.isEmpty()) "-" else t.liveValues.joinToString(",")} → ${t.afterValue}",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = c
                                    )
                                }
                            }
                        }
                    }
                    items(report.sessionFlow, key = { it.id }) { event ->
                        TelemetrySectionCard {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = "${event.phase} · ${event.component}",
                                    style = MaterialTheme.typography.titleSmall,
                                    modifier = Modifier.weight(1f)
                                )
                                StatusPill(status = event.status)
                            }
                            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                KnowledgeBadge(level = event.knowledgeLevel)
                                if (event.isBenignWarning) {
                                    TagChip(strings.benignWarningTag, LocalFodStatusColors.current.suspect)
                                }
                                if (event.isBlockingFailure) {
                                    TagChip(strings.blockingBreakTag, LocalFodStatusColors.current.failed)
                                }
                            }
                            Text(event.summary, style = MaterialTheme.typography.bodyMedium)
                            Text(
                                text = event.rawEvidence,
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }

                1 -> { // COMPONENT INTELLIGENCE + PATCHES + ELF
                    item {
                        OutlinedTextField(
                            value = componentFilter,
                            onValueChange = { componentFilter = it },
                            label = { Text(strings.searchComponentsHint) },
                            leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                    item {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .horizontalScroll(rememberScrollState()),
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            FilterChip(
                                selected = statusFilter == null,
                                onClick = { statusFilter = null },
                                label = { Text("ALL (${report.components.size})") }
                            )
                            EvidenceStatus.entries.forEach { st ->
                                FilterChip(
                                    selected = statusFilter == st,
                                    onClick = { statusFilter = if (statusFilter == st) null else st },
                                    label = { Text(st.name) }
                                )
                            }
                        }
                    }
                    val filteredComponents = report.components.filter { c ->
                        val matchesStatus = statusFilter == null || c.status == statusFilter
                        val q = componentFilter.trim().lowercase()
                        val matchesQuery = q.isEmpty() ||
                            c.name.lowercase().contains(q) ||
                            c.path.lowercase().contains(q) ||
                            c.category.name.lowercase().contains(q)
                        matchesStatus && matchesQuery
                    }
                    items(filteredComponents, key = { it.id }) { comp ->
                        var expandedComp by remember { mutableStateOf(false) }
                        TelemetrySectionCard(
                            modifier = Modifier.clickable(enabled = comp.metadata.isNotEmpty()) { expandedComp = !expandedComp }
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(comp.name, style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
                                StatusPill(status = comp.status)
                            }
                            Text(
                                text = "${comp.category} · ${comp.version} · ${comp.interfaceType}",
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.primary
                            )
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = comp.path,
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.weight(1f)
                                )
                                if (comp.path.startsWith("/")) {
                                    IconButton(
                                        onClick = { copyPathToClipboard(context, comp.path) },
                                        modifier = Modifier.size(48.dp)
                                    ) {
                                        Icon(
                                            Icons.Filled.ContentCopy,
                                            contentDescription = strings.portCopyPathLabel,
                                            modifier = Modifier.size(16.dp)
                                        )
                                    }
                                }
                            }
                            if (comp.dependencies.isNotEmpty()) {
                                Text(
                                    text = "Deps: ${comp.dependencies.joinToString(", ")}",
                                    style = MaterialTheme.typography.bodySmall
                                )
                            }
                            if (comp.accessNote != null) {
                                Text(
                                    text = comp.accessNote,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = LocalFodStatusColors.current.suspect
                                )
                            }
                            AnimatedVisibility(visible = expandedComp && comp.metadata.isNotEmpty()) {
                                Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                                    HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                                    comp.metadata.forEach { (k, v) ->
                                        Text(
                                            text = "$k: $v",
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                }
                            }
                        }
                    }

                    // Deep Overlay & Dynamic File Provenance Section
                    if (report.overlayInspections.isNotEmpty() || report.fileProvenance.isNotEmpty()) {
                        item {
                            Text(
                                text = "${strings.provenanceDiagnosticTitle} (${report.overlayInspections.size} RRO · ${report.fileProvenance.size} files)",
                                style = MaterialTheme.typography.titleMedium,
                                modifier = Modifier.padding(top = 8.dp)
                            )
                        }
                        items(report.overlayInspections, key = { "ov_insp_${it.packageName}" }) { ov ->
                            var expandedOv by remember { mutableStateOf(false) }
                            TelemetrySectionCard(
                                borderColor = if (ov.isEnabled) LocalFodStatusColors.current.confirmed.copy(alpha = 0.6f) else MaterialTheme.colorScheme.outline.copy(alpha = 0.5f),
                                modifier = Modifier.clickable { expandedOv = !expandedOv }
                            ) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(ov.packageName, style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
                                    StatusPill(status = if (ov.isEnabled) EvidenceStatus.CONFIRMED else EvidenceStatus.OBSERVED)
                                }
                                Text(
                                    text = "Target: ${ov.targetPackage.ifBlank { "?" }} · prio=${ov.priority} · static=${ov.isStatic}",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.primary
                                )
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text("APK: ${ov.apkPath}", style = MaterialTheme.typography.labelSmall)
                                        Text("Dir: ${ov.directory}", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                    }
                                    if (ov.apkPath.startsWith("/")) {
                                        IconButton(
                                            onClick = { copyPathToClipboard(context, ov.apkPath) },
                                            modifier = Modifier.size(48.dp)
                                        ) {
                                            Icon(Icons.Filled.ContentCopy, contentDescription = strings.portCopyPathLabel, modifier = Modifier.size(16.dp))
                                        }
                                    }
                                    Icon(
                                        imageVector = if (expandedOv) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                                        contentDescription = null,
                                        modifier = Modifier.size(20.dp)
                                    )
                                }
                                AnimatedVisibility(visible = expandedOv) {
                                    Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                                        HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                                        ov.manifestSummary.forEach { m ->
                                            Text("• $m", style = MaterialTheme.typography.labelSmall)
                                        }
                                        ov.fodConfigEntries.forEach { entry ->
                                            Text("• $entry", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary)
                                        }
                                    }
                                }
                            }
                        }
                        items(report.fileProvenance.filter { it.category != "OVERLAY_APK" }, key = { "prov_card_${it.id}_${it.filePath}" }) { prov ->
                            var expandedProv by remember { mutableStateOf(false) }
                            TelemetrySectionCard(modifier = Modifier.clickable { expandedProv = !expandedProv }) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text("[${prov.category}] ${prov.filePath.substringAfterLast('/')}", style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
                                    Icon(
                                        imageVector = if (expandedProv) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                                        contentDescription = null,
                                        modifier = Modifier.size(20.dp)
                                    )
                                }
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(prov.filePath, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary)
                                        Text("${strings.portSourceDirLabel}: ${prov.directory}", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                    }
                                    if (prov.filePath.startsWith("/")) {
                                        IconButton(
                                            onClick = { copyPathToClipboard(context, prov.filePath) },
                                            modifier = Modifier.size(48.dp)
                                        ) {
                                            Icon(Icons.Filled.ContentCopy, contentDescription = strings.portCopyPathLabel, modifier = Modifier.size(16.dp))
                                        }
                                    }
                                }
                                AnimatedVisibility(visible = expandedProv) {
                                    Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                                        HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                                        prov.importantContents.forEach { line ->
                                            Text("• $line", style = MaterialTheme.typography.labelSmall)
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Exhaustive Patches Section
                    item {
                        Text(
                            text = "${strings.patchesDetectedTitle} (${report.patches.size})",
                            style = MaterialTheme.typography.titleMedium,
                            modifier = Modifier.padding(top = 8.dp)
                        )
                    }
                    items(report.patches, key = { it.id }) { patch ->
                        TelemetrySectionCard {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(patch.name, style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
                                StatusPill(status = patch.status)
                            }
                            Text("${patch.scope} · ${patch.source}", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.secondary)
                            Text("Value: ${patch.rawValue}", style = MaterialTheme.typography.labelSmall)
                            Text(patch.realObservedEffect, style = MaterialTheme.typography.bodySmall)
                            if (patch.note.isNotBlank() && patch.note != patch.name) {
                                Text(patch.note, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                    }

                    // ELF Disassembly Section
                    item {
                        Text(
                            text = "${strings.elfAnalysisTitle} (${report.elfAnalyses.size})",
                            style = MaterialTheme.typography.titleMedium,
                            modifier = Modifier.padding(top = 8.dp)
                        )
                    }
                    items(report.elfAnalyses, key = { it.path }) { elf ->
                        var expanded by remember { mutableStateOf(false) }
                        TelemetrySectionCard(modifier = Modifier.clickable { expanded = !expanded }) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(elf.path.substringAfterLast('/'), style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
                                StatusPill(status = if (elf.isReadable) EvidenceStatus.CONFIRMED else EvidenceStatus.UNKNOWN)
                            }
                            Text("${elf.architecture} · ${elf.fileSizeBytes} bytes · ${elf.fodSymbols.size} symbols", style = MaterialTheme.typography.labelMedium)
                            if (elf.accessError != null) {
                                Text(elf.accessError, style = MaterialTheme.typography.bodySmall, color = LocalFodStatusColors.current.suspect)
                            }
                            AnimatedVisibility(visible = expanded) {
                                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                    HorizontalDivider()
                                    if (elf.dtNeeded.isNotEmpty()) {
                                        Text("DT_NEEDED: ${elf.dtNeeded.joinToString(", ")}", style = MaterialTheme.typography.labelSmall)
                                    }
                                    if (elf.fodSymbols.isNotEmpty()) {
                                        Text("Symbols:\n${elf.fodSymbols.take(25).joinToString("\n")}", style = MaterialTheme.typography.labelSmall)
                                    }
                                    if (elf.disassemblyPseudoCode.isNotBlank()) {
                                        Text(
                                            text = elf.disassemblyPseudoCode.take(3500),
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.primary
                                        )
                                    }
                                }
                            }
                        }
                    }
                }

                2 -> { // DEPENDENCY GRAPH
                    item {
                        InteractiveDependencyGraph(
                            components = report.components,
                            edges = report.dependencyEdges
                        )
                    }
                }

                3 -> { // LIVE INVESTIGATION
                    items(report.findings, key = { it.id }) { f ->
                        TelemetrySectionCard {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(f.title, style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
                                StatusPill(status = f.status)
                            }
                            KnowledgeBadge(level = f.knowledgeLevel)
                            Text(f.detail, style = MaterialTheme.typography.bodyMedium)
                            if (f.evidenceSnippet.isNotBlank()) {
                                Text(
                                    text = f.evidenceSnippet,
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }

                4 -> { // DIAGNOSTIC SUMMARY + GEMINI HIGH THINKING
                    item {
                        SummaryTabContent(
                            report = report,
                            aiState = aiState,
                            onRegenerateAi = { viewModel.runAiSynthesis(language) }
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun ModeCard(
    title: String,
    description: String,
    selected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val borderColor = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline.copy(alpha = 0.6f)
    val bgColor = if (selected) MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.55f) else MaterialTheme.colorScheme.surface
    Card(
        modifier = modifier
            .heightIn(min = 84.dp)
            .clickable(onClick = onClick),
        shape = MaterialTheme.shapes.medium,
        colors = CardDefaults.cardColors(containerColor = bgColor),
        border = BorderStroke(if (selected) 2.dp else 1.dp, borderColor)
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleSmall,
                color = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface
            )
            Text(
                text = description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 3,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
private fun DashboardHeaderCard(report: FodDiagnosticReport) {
    val strings = LocalAppStrings.current
    val statusColors = LocalFodStatusColors.current
    TelemetrySectionCard(
        containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "${strings.dashboardTitle} · ${report.mode.name}",
                style = MaterialTheme.typography.titleMedium
            )
            Text(
                text = "#${report.sessionId}",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.primary
            )
        }
        Text(
            text = report.summary.overallOutcome,
            style = MaterialTheme.typography.titleSmall,
            color = when (report.summary.enrollmentSucceeded) {
                true -> statusColors.confirmed
                false -> statusColors.failed
                null -> statusColors.observed
            }
        )
        Text(
            text = "${report.environment.deviceModel} · Android ${report.environment.androidRelease} · SELinux=${report.environment.selinuxMode} · Root=${report.environment.rootGranted}",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            TagChip("CONFIRMED: ${report.summary.confirmedCount}", statusColors.confirmed)
            TagChip("OBSERVED: ${report.summary.observedCount}", statusColors.observed)
            TagChip("SUSPECT: ${report.summary.suspectCount}", statusColors.suspect)
            TagChip("FAILED: ${report.summary.failedCount}", statusColors.failed)
            TagChip("UNKNOWN: ${report.summary.unknownCount}", statusColors.unknown)
        }
    }
}

@Composable
private fun SummaryTabContent(
    report: FodDiagnosticReport,
    aiState: AiSynthesisState,
    onRegenerateAi: () -> Unit
) {
    val strings = LocalAppStrings.current
    val statusColors = LocalFodStatusColors.current
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        TelemetrySectionCard {
            Text(strings.firstBreakTitle, style = MaterialTheme.typography.titleSmall, color = statusColors.failed)
            Text(report.summary.firstDemonstratedBreak, style = MaterialTheme.typography.bodyMedium)
            HorizontalDivider()
            Text(strings.successDespiteNoiseTitle, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
            Text(report.summary.realSuccessDespiteNoiseNote, style = MaterialTheme.typography.bodyMedium)
            if (report.fingerDownChain.isNotEmpty()) {
                HorizontalDivider()
                Text(strings.fingerDownChainTitle, style = MaterialTheme.typography.titleSmall)
                report.fingerDownChain.forEach { st ->
                    Text(
                        text = "[${st.status}] ${st.stage}: ${st.detail}",
                        style = MaterialTheme.typography.bodySmall,
                        color = when (st.status) {
                            EvidenceStatus.CONFIRMED -> statusColors.confirmed
                            EvidenceStatus.FAILED -> statusColors.failed
                            EvidenceStatus.SUSPECT -> statusColors.suspect
                            else -> MaterialTheme.colorScheme.onSurfaceVariant
                        }
                    )
                }
            }
        }

        if (report.environment.accessLimitations.isNotEmpty()) {
            TelemetrySectionCard(borderColor = statusColors.suspect) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    Icon(Icons.Filled.Warning, contentDescription = null, tint = statusColors.suspect, modifier = Modifier.size(18.dp))
                    Text(strings.accessLimitationsTitle, style = MaterialTheme.typography.titleSmall)
                }
                report.environment.accessLimitations.take(10).forEach { limit ->
                    Text("• $limit", style = MaterialTheme.typography.bodySmall)
                }
            }
        }

        // Gemini 4 Carbon High Thinking Card
        TelemetrySectionCard(borderColor = MaterialTheme.colorScheme.tertiary.copy(alpha = 0.7f)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp), modifier = Modifier.weight(1f)) {
                    Icon(Icons.Filled.AutoAwesome, contentDescription = null, tint = MaterialTheme.colorScheme.tertiary)
                    Text(strings.aiSynthesisTitle, style = MaterialTheme.typography.titleSmall)
                }
                TagChip(strings.aiThinkingBadge, MaterialTheme.colorScheme.tertiary)
            }

            when (aiState) {
                AiSynthesisState.Idle -> {
                    Button(onClick = onRegenerateAi, modifier = Modifier.heightIn(min = 48.dp)) {
                        Icon(Icons.Filled.AutoAwesome, contentDescription = null)
                        Spacer(Modifier.width(6.dp))
                        Text(strings.btnRunAiThinking)
                    }
                }
                AiSynthesisState.Loading -> {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                        Text("Thinking (HIGH)...", style = MaterialTheme.typography.bodySmall)
                    }
                }
                is AiSynthesisState.Streaming -> {
                    LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                    Text(aiState.text, style = MaterialTheme.typography.bodyMedium)
                }
                is AiSynthesisState.Success -> {
                    Text(aiState.text, style = MaterialTheme.typography.bodyMedium)
                    TextButton(onClick = onRegenerateAi) {
                        Icon(Icons.Filled.Refresh, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp))
                        Text(strings.btnRunAiThinking)
                    }
                }
                is AiSynthesisState.Error -> {
                    Text(aiState.message, color = statusColors.failed, style = MaterialTheme.typography.bodySmall)
                    OutlinedButton(onClick = onRegenerateAi, modifier = Modifier.heightIn(min = 48.dp)) {
                        Text(strings.btnRunAiThinking)
                    }
                }
            }
        }
    }
}

@Composable
private fun TagChip(text: String, color: androidx.compose.ui.graphics.Color) {
    Surface(
        color = color.copy(alpha = 0.14f),
        shape = RoundedCornerShape(6.dp),
        border = BorderStroke(1.dp, color.copy(alpha = 0.45f))
    ) {
        Text(
            text = text,
            modifier = Modifier.padding(horizontal = 7.dp, vertical = 3.dp),
            style = MaterialTheme.typography.labelSmall,
            color = color,
            fontWeight = FontWeight.Bold
        )
    }
}

private fun openFingerprintEnrollmentSettings(context: Context) {
    val intents = listOf(
        Intent("android.settings.FINGERPRINT_ENROLL"),
        Intent(Settings.ACTION_BIOMETRIC_ENROLL),
        Intent(Settings.ACTION_SECURITY_SETTINGS),
        Intent(Settings.ACTION_SETTINGS)
    )
    for (intent in intents) {
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (intent.resolveActivity(context.packageManager) != null) {
            context.startActivity(intent)
            return
        }
    }
}

private fun copyPathToClipboard(context: Context, path: String) {
    val cm = context.getSystemService(ClipboardManager::class.java) ?: return
    cm.setPrimaryClip(ClipData.newPlainText("FOD Path", path))
    Toast.makeText(context, path, Toast.LENGTH_SHORT).show()
}
