package com.example.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
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
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Verified
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.i18n.AppLanguage
import com.example.i18n.LocalAppStrings
import com.example.model.EvidenceStatus
import com.example.model.ExtractableFileItem
import com.example.model.PortingCandidateSolution
import com.example.model.RawZipArchiveBundle
import com.example.ui.components.KnowledgeBadge
import com.example.ui.components.PortCausalComparisonSection
import com.example.ui.components.StatusPill
import com.example.ui.components.TelemetrySectionCard
import com.example.ui.theme.LocalFodStatusColors
import com.example.viewmodel.PortPhase
import com.example.viewmodel.PortViewModel

@Composable
fun PortScreen(
    viewModel: PortViewModel,
    allFilesGranted: Boolean,
    language: AppLanguage,
    modifier: Modifier = Modifier
) {
    val strings = LocalAppStrings.current
    val context = LocalContext.current
    val statusColors = LocalFodStatusColors.current

    val romArchive by viewModel.romArchive.collectAsStateWithLifecycle()
    val gsiArchive by viewModel.gsiArchive.collectAsStateWithLifecycle()
    val portResult by viewModel.portResult.collectAsStateWithLifecycle()
    val portPhase by viewModel.portPhase.collectAsStateWithLifecycle()
    val aiStreamText by viewModel.aiStreamText.collectAsStateWithLifecycle()
    val aiProviderLabel by viewModel.aiProviderLabel.collectAsStateWithLifecycle()
    val importError by viewModel.importError.collectAsStateWithLifecycle()
    val exportState by viewModel.exportState.collectAsStateWithLifecycle()

    var activeSubTab by rememberSaveable { mutableIntStateOf(0) }
    var diffQuery by rememberSaveable { mutableStateOf("") }
    var onlyFailedDiffs by rememberSaveable { mutableStateOf(false) }
    var showExportMenu by remember { mutableStateOf(false) }

    val romZipPicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) viewModel.importZip(isRom = true, uri = uri)
    }

    val gsiZipPicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) viewModel.importZip(isRom = false, uri = uri)
    }

    val htmlExportLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("text/html")
    ) { uri ->
        if (uri != null) viewModel.exportPortReport(asHtml = true, language = language, targetUri = uri)
    }

    val mdExportLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("text/markdown")
    ) { uri ->
        if (uri != null) viewModel.exportPortReport(asHtml = false, language = language, targetUri = uri)
    }

    val isBusy = portPhase is PortPhase.ReadingZips || portPhase is PortPhase.AnalyzingDiffs

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        contentPadding = PaddingValues(top = 12.dp, bottom = 28.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Text(strings.portTitle, style = MaterialTheme.typography.headlineSmall)
        }

        // Scope & full-ZIP factual invariant banner
        item {
            TelemetrySectionCard(
                containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.45f),
                borderColor = MaterialTheme.colorScheme.primary
            ) {
                Text(strings.portSubtitleBanner, style = MaterialTheme.typography.bodySmall)
            }
        }

        // Dual ZIP Deep Importers (Custom ROM + GSI)
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                PortZipImportCard(
                    title = strings.portImportRomLabel,
                    bundle = romArchive,
                    onPickZip = { romZipPicker.launch(arrayOf("application/zip", "application/octet-stream", "*/*")) },
                    onLoadLocal = { viewModel.loadFromLocalSession(isRom = true) },
                    modifier = Modifier
                        .weight(1f)
                        .testTag("port_import_rom")
                )
                PortZipImportCard(
                    title = strings.portImportGsiLabel,
                    bundle = gsiArchive,
                    onPickZip = { gsiZipPicker.launch(arrayOf("application/zip", "application/octet-stream", "*/*")) },
                    onLoadLocal = { viewModel.loadFromLocalSession(isRom = false) },
                    modifier = Modifier
                        .weight(1f)
                        .testTag("port_import_gsi")
                )
            }
        }

        if (importError != null) {
            item {
                TelemetrySectionCard(borderColor = statusColors.failed) {
                    Text(importError.orEmpty(), color = statusColors.failed, style = MaterialTheme.typography.bodySmall)
                }
            }
        }

        // Analyze + Export Controls
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Button(
                    onClick = { viewModel.analyzePorting(language) },
                    enabled = romArchive != null && gsiArchive != null && !isBusy && portPhase !is PortPhase.RunningAi,
                    modifier = Modifier
                        .weight(1f)
                        .heightIn(min = 50.dp)
                        .testTag("btn_run_port_analysis")
                ) {
                    if (isBusy || portPhase is PortPhase.RunningAi) {
                        CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                    } else {
                        Icon(Icons.Filled.Build, contentDescription = strings.portBtnAnalyze)
                    }
                    Spacer(Modifier.width(6.dp))
                    Text(strings.portBtnAnalyze, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }

                Box {
                    OutlinedButton(
                        onClick = { showExportMenu = true },
                        enabled = portResult != null && !exportState.isExporting,
                        modifier = Modifier
                            .heightIn(min = 50.dp)
                            .testTag("btn_export_port")
                    ) {
                        Icon(Icons.Filled.Download, contentDescription = strings.portExportReportLabel)
                    }
                    DropdownMenu(
                        expanded = showExportMenu,
                        onDismissRequest = { showExportMenu = false }
                    ) {
                        DropdownMenuItem(
                            text = { Text(strings.btnExportSingleHtml) },
                            onClick = {
                                showExportMenu = false
                                if (allFilesGranted) {
                                    viewModel.exportPortReport(asHtml = true, language = language, targetUri = null)
                                } else {
                                    htmlExportLauncher.launch("fod_port_dossier.html")
                                }
                            }
                        )
                        DropdownMenuItem(
                            text = { Text(strings.btnExportSingleMd) },
                            onClick = {
                                showExportMenu = false
                                if (allFilesGranted) {
                                    viewModel.exportPortReport(asHtml = false, language = language, targetUri = null)
                                } else {
                                    mdExportLauncher.launch("fod_port_dossier.md")
                                }
                            }
                        )
                    }
                }
            }
        }

        // Phase / Export progress banners
        if (portPhase !is PortPhase.Idle) {
            item {
                TelemetrySectionCard {
                    when (val ph = portPhase) {
                        PortPhase.ReadingZips -> {
                            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                            Text(strings.portReadingZips, style = MaterialTheme.typography.bodySmall)
                        }
                        PortPhase.AnalyzingDiffs, PortPhase.RunningAi -> {
                            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                            Text(strings.portRunningDeepAi, style = MaterialTheme.typography.bodySmall)
                        }
                        is PortPhase.Error -> {
                            Text(ph.message, color = statusColors.failed, style = MaterialTheme.typography.bodySmall)
                        }
                        PortPhase.Idle -> Unit
                    }
                }
            }
        }

        if (exportState.isExporting || exportState.message != null) {
            item {
                TelemetrySectionCard(
                    borderColor = if (exportState.isError) statusColors.failed else statusColors.confirmed
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
                            IconButton(onClick = { viewModel.clearExportMessage() }) {
                                Icon(Icons.Filled.Close, contentDescription = "Dismiss")
                            }
                        }
                    }
                }
            }
        }

        val result = portResult
        if (result == null) {
            item {
                TelemetrySectionCard {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 22.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(Icons.Filled.Build, contentDescription = null, modifier = Modifier.size(44.dp), tint = MaterialTheme.colorScheme.primary)
                        Text(strings.portEmptyTitle, style = MaterialTheme.typography.titleLarge)
                        Text(strings.portEmptyBody, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
        } else {
            // Boot / Vendor Parity + Files Read Summary
            item {
                TelemetrySectionCard(
                    borderColor = if (result.bootVendorParityVerified) statusColors.confirmed else statusColors.suspect
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Icon(
                            imageVector = if (result.bootVendorParityVerified) Icons.Filled.Verified else Icons.Filled.Warning,
                            contentDescription = null,
                            tint = if (result.bootVendorParityVerified) statusColors.confirmed else statusColors.suspect
                        )
                        Text(
                            text = if (result.bootVendorParityVerified) strings.bootVendorParityOk else strings.bootVendorParityWarn,
                            style = MaterialTheme.typography.titleSmall
                        )
                    }
                    Text(
                        text = "${result.romFilesRead} fichiers ROM (${result.romTotalBytes / 1024} Ko) vs ${result.gsiFilesRead} fichiers GSI (${result.gsiTotalBytes / 1024} Ko)",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.primary
                    )
                    Text(result.bootVendorParitySummary, style = MaterialTheme.typography.labelSmall)
                }
            }

            // Sub-Tabs: VERDICT & IA | FICHIERS A EXTRAIRE | SOLUTIONS DE PORTAGE | DIFF INTEGRAL ZIP
            item {
                val subTabs = listOf(
                    strings.portSubTabVerdict,
                    "${strings.portSubTabExtractables} (${result.extractableFiles.size})",
                    "${strings.portSubTabSolutions} (${result.portingSolutions.size})",
                    "${strings.portSubTabFileDiffs} (${result.factualDiffs.size})"
                )
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    subTabs.forEachIndexed { idx, label ->
                        FilterChip(
                            selected = activeSubTab == idx,
                            onClick = { activeSubTab = idx },
                            label = { Text(label) },
                            modifier = Modifier.testTag("port_subtab_$idx")
                        )
                    }
                }
            }

            when (activeSubTab) {
                0 -> {
                    item {
                        TelemetrySectionCard(borderColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.7f)) {
                            Text(strings.portSubTabVerdict, style = MaterialTheme.typography.titleSmall)
                            Text(result.factualRootCauseVerdict, style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                    if (result.romCausalChain.isNotEmpty()) {
                        item {
                            PortCausalComparisonSection(
                                romChain = result.romCausalChain,
                                gsiChain = result.gsiCausalChain,
                                breakSummary = result.causalBreakSummary,
                                filteredNonFodOverlayCount = result.filteredNonFodOverlayCount
                            )
                        }
                    }
                    item {
                        TelemetrySectionCard(borderColor = MaterialTheme.colorScheme.tertiary.copy(alpha = 0.7f)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                    Icon(Icons.Filled.AutoAwesome, contentDescription = null, tint = MaterialTheme.colorScheme.tertiary)
                                    Text(strings.aiSynthesisTitle, style = MaterialTheme.typography.titleSmall)
                                }
                            }
                            if (aiProviderLabel.isNotBlank() || result.aiProviderUsed.isNotBlank()) {
                                Surface(
                                    color = MaterialTheme.colorScheme.tertiaryContainer,
                                    shape = RoundedCornerShape(6.dp)
                                ) {
                                    Text(
                                        text = aiProviderLabel.ifBlank { result.aiProviderUsed },
                                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                                        style = MaterialTheme.typography.labelSmall,
                                        fontWeight = FontWeight.Bold
                                    )
                                }
                            }
                            val textToRender = aiStreamText.ifBlank { result.aiFactualSynthesis }
                            if (textToRender.isBlank() && portPhase is PortPhase.RunningAi) {
                                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                            } else {
                                Text(textToRender, style = MaterialTheme.typography.bodyMedium)
                            }
                        }
                    }
                }

                1 -> {
                    if (result.extractableFiles.isEmpty()) {
                        item {
                            TelemetrySectionCard {
                                Text(
                                    text = strings.portEmptyBody,
                                    style = MaterialTheme.typography.bodyMedium
                                )
                            }
                        }
                    } else {
                        items(result.extractableFiles, key = { "${it.category}::${it.romFilePath}::${it.title}" }) { ex ->
                            ExtractableFileCard(
                                item = ex,
                                onCopyPath = { copyPortPathToClipboard(context, it) }
                            )
                        }
                    }
                }

                2 -> {
                    items(result.portingSolutions, key = { it.id }) { sol ->
                        PortSolutionCard(solution = sol)
                    }
                }

                else -> {
                    item {
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedTextField(
                                value = diffQuery,
                                onValueChange = { diffQuery = it },
                                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                                placeholder = { Text(strings.portSearchDiffsHint) },
                                singleLine = true,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .testTag("port_diff_search")
                            )
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                FilterChip(
                                    selected = onlyFailedDiffs,
                                    onClick = { onlyFailedDiffs = !onlyFailedDiffs },
                                    label = { Text("[FAILED] uniquement (${result.factualDiffs.count { it.status == EvidenceStatus.FAILED }})") }
                                )
                                Text(
                                    text = "${result.filteredSharedNoiseCount} ${strings.portSharedNoiseFiltered}",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = statusColors.confirmed,
                                    modifier = Modifier.weight(1f).padding(start = 8.dp)
                                )
                            }
                        }
                    }
                    val filtered = result.factualDiffs.filter { d ->
                        val matchStatus = !onlyFailedDiffs || d.status == EvidenceStatus.FAILED
                        val matchQuery = diffQuery.isBlank() ||
                            d.title.contains(diffQuery, true) ||
                            d.sourceFile.contains(diffQuery, true) ||
                            d.category.contains(diffQuery, true) ||
                            d.romEvidence.contains(diffQuery, true) ||
                            d.gsiEvidence.contains(diffQuery, true)
                        matchStatus && matchQuery
                    }
                    items(filtered, key = { "${it.sourceFile}::${it.title}" }) { d ->
                        TelemetrySectionCard {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(d.title, style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
                                StatusPill(status = d.status)
                            }
                            Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
                                KnowledgeBadge(level = d.knowledgeLevel)
                                Text("${d.category} · ${d.sourceFile}", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary)
                            }
                            Text("ROM: ${d.romEvidence}", style = MaterialTheme.typography.labelSmall, color = statusColors.confirmed)
                            Text("GSI: ${d.gsiEvidence}", style = MaterialTheme.typography.labelSmall, color = statusColors.failed)
                            HorizontalDivider()
                            Text(d.impact, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun PortZipImportCard(
    title: String,
    bundle: RawZipArchiveBundle?,
    onPickZip: () -> Unit,
    onLoadLocal: () -> Unit,
    modifier: Modifier = Modifier
) {
    val strings = LocalAppStrings.current
    val statusColors = LocalFodStatusColors.current
    TelemetrySectionCard(
        modifier = modifier,
        borderColor = if (bundle != null) statusColors.confirmed else MaterialTheme.colorScheme.outline.copy(alpha = 0.6f)
    ) {
        Text(title, style = MaterialTheme.typography.titleSmall)
        if (bundle != null) {
            Text(
                text = bundle.sourceName,
                style = MaterialTheme.typography.labelSmall,
                color = statusColors.confirmed,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
            Text(
                text = "${bundle.totalFiles} fichiers · ${bundle.totalBytes / 1024} Ko",
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Bold
            )
        } else {
            Text("—", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        OutlinedButton(
            onClick = onPickZip,
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 48.dp)
        ) {
            Icon(Icons.Filled.FolderOpen, contentDescription = strings.btnImportZip, modifier = Modifier.size(16.dp))
            Spacer(Modifier.width(4.dp))
            Text(strings.btnImportZip, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        TextButton(
            onClick = onLoadLocal,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Session locale", style = MaterialTheme.typography.labelSmall)
        }
    }
}

@Composable
private fun PortSolutionCard(solution: PortingCandidateSolution) {
    val strings = LocalAppStrings.current
    val statusColors = LocalFodStatusColors.current
    TelemetrySectionCard(
        borderColor = if (solution.confidencePercent >= 85) statusColors.confirmed else MaterialTheme.colorScheme.outline
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("#${solution.rank} · ${solution.title}", style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
            Surface(
                color = statusColors.confirmedContainer,
                shape = RoundedCornerShape(6.dp)
            ) {
                Text(
                    text = "${solution.confidencePercent}%",
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                    style = MaterialTheme.typography.labelSmall,
                    color = statusColors.confirmed,
                    fontWeight = FontWeight.Bold
                )
            }
        }
        Surface(
            color = if (!solution.requiresFrameworkOrSystemUi) statusColors.confirmedContainer else statusColors.suspectContainer,
            shape = RoundedCornerShape(6.dp)
        ) {
            Text(
                text = if (!solution.requiresFrameworkOrSystemUi) strings.noFrameworkChangeBadge else strings.frameworkChangeBadge,
                modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                style = MaterialTheme.typography.labelSmall,
                color = if (!solution.requiresFrameworkOrSystemUi) statusColors.confirmed else statusColors.suspect,
                fontWeight = FontWeight.Bold
            )
        }
        Text(solution.layer, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary)
        Text(solution.whyItApplies, style = MaterialTheme.typography.bodyMedium)
        HorizontalDivider()
        solution.concreteActionSteps.forEachIndexed { idx, step ->
            Text("${idx + 1}. $step", style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Medium)
        }
        if (solution.exactSourcesInZip.isNotEmpty()) {
            solution.exactSourcesInZip.take(5).forEach { src ->
                Text("• $src", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        Text("Limits: ${solution.limitations}", style = MaterialTheme.typography.labelSmall, color = statusColors.suspect)
    }
}

@Composable
private fun ExtractableFileCard(
    item: ExtractableFileItem,
    onCopyPath: (String) -> Unit
) {
    val strings = LocalAppStrings.current
    val statusColors = LocalFodStatusColors.current
    var expanded by rememberSaveable(item.id) { mutableStateOf(item.priorityPercent >= 88) }

    TelemetrySectionCard(
        borderColor = if (item.priorityPercent >= 88) statusColors.confirmed else MaterialTheme.colorScheme.outline,
        modifier = Modifier.clickable { expanded = !expanded }
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(item.category, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary)
                Text(item.title, style = MaterialTheme.typography.titleSmall)
            }
            Surface(
                color = statusColors.confirmedContainer,
                shape = RoundedCornerShape(6.dp)
            ) {
                Text(
                    text = "${item.priorityPercent}%",
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                    style = MaterialTheme.typography.labelSmall,
                    color = statusColors.confirmed,
                    fontWeight = FontWeight.Bold
                )
            }
        }

        if (item.canExtractWithoutVendorOrBoot) {
            Surface(
                color = statusColors.confirmedContainer,
                shape = RoundedCornerShape(6.dp)
            ) {
                Text(
                    text = "BOOT & VENDOR INTACTS",
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                    style = MaterialTheme.typography.labelSmall,
                    color = statusColors.confirmed,
                    fontWeight = FontWeight.Bold
                )
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = item.romFilePath,
                    style = MaterialTheme.typography.labelSmall,
                    color = statusColors.confirmed,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    text = "${strings.portSourceDirLabel}: ${item.romDirectory}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = "${strings.portTargetGsiLabel}: ${item.targetGsiPath}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.primary
                )
            }
            IconButton(
                onClick = { onCopyPath(item.romFilePath) },
                modifier = Modifier
                    .size(48.dp)
                    .testTag("copy_extractable_${item.id}")
            ) {
                Icon(
                    imageVector = Icons.Filled.ContentCopy,
                    contentDescription = strings.portCopyPathLabel,
                    modifier = Modifier.size(18.dp)
                )
            }
        }

        Text(item.missingMechanism, style = MaterialTheme.typography.bodySmall)
        Text("GSI: ${item.gsiCurrentState}", style = MaterialTheme.typography.labelSmall, color = statusColors.failed)

        if (item.importantElements.isNotEmpty()) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "${strings.portImportantContentsLabel} (${item.importantElements.size})",
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.primary
                )
                Icon(
                    imageVector = if (expanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                    contentDescription = null,
                    modifier = Modifier.size(20.dp)
                )
            }
            AnimatedVisibility(visible = expanded) {
                val codeLines = remember(item.importantElements) {
                    item.importantElements.filter { line ->
                        line.startsWith("ARSC ") ||
                            line.startsWith("CLASS:") ||
                            line.startsWith("METHOD:") ||
                            line.startsWith("LOOKUP") ||
                            line.startsWith("<") ||
                            line.startsWith("SCORE=") ||
                            line.startsWith("---") ||
                            line.startsWith("XML:")
                    }
                }
                val noteLines = remember(item.importantElements, codeLines) {
                    item.importantElements.filter { it !in codeLines }
                }
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                    noteLines.forEach { line ->
                        Text("• $line", style = MaterialTheme.typography.labelSmall)
                    }
                    if (codeLines.isNotEmpty()) {
                        Surface(
                            color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.7f),
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(
                                text = codeLines.joinToString("\n"),
                                style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                                modifier = Modifier.padding(8.dp)
                            )
                        }
                    }
                }
            }
        }
    }
}

private fun copyPortPathToClipboard(context: Context, path: String) {
    val cm = context.getSystemService(ClipboardManager::class.java) ?: return
    cm.setPrimaryClip(ClipData.newPlainText("FOD Path", path))
    Toast.makeText(context, path, Toast.LENGTH_SHORT).show()
}
