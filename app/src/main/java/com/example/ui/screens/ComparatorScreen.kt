package com.example.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
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
import androidx.compose.material.icons.filled.CompareArrows
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Verified
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
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
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.i18n.AppLanguage
import com.example.i18n.LocalAppStrings
import com.example.model.ComparisonEntry
import com.example.model.FodDiagnosticReport
import com.example.ui.components.KnowledgeBadge
import com.example.ui.components.StatusPill
import com.example.ui.components.TelemetrySectionCard
import com.example.ui.theme.LocalFodStatusColors
import com.example.viewmodel.AiSynthesisState
import com.example.viewmodel.ComparatorViewModel

@Composable
fun ComparatorScreen(
    viewModel: ComparatorViewModel,
    allFilesGranted: Boolean,
    language: AppLanguage,
    modifier: Modifier = Modifier
) {
    val strings = LocalAppStrings.current
    val statusColors = LocalFodStatusColors.current

    val romReport by viewModel.romReport.collectAsStateWithLifecycle()
    val gsiReport by viewModel.gsiReport.collectAsStateWithLifecycle()
    val comparison by viewModel.comparisonResult.collectAsStateWithLifecycle()
    val aiState by viewModel.aiComparisonState.collectAsStateWithLifecycle()
    val importError by viewModel.importError.collectAsStateWithLifecycle()
    val exportState by viewModel.exportState.collectAsStateWithLifecycle()

    var activeSection by rememberSaveable { mutableIntStateOf(0) }
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
        if (uri != null) viewModel.exportComparison(asHtml = true, language = language, targetUri = uri)
    }

    val mdExportLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("text/markdown")
    ) { uri ->
        if (uri != null) viewModel.exportComparison(asHtml = false, language = language, targetUri = uri)
    }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        contentPadding = PaddingValues(top = 12.dp, bottom = 28.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Text(strings.comparatorTitle, style = MaterialTheme.typography.headlineSmall)
        }

        // Immutable boot & vendor invariant banner
        item {
            TelemetrySectionCard(
                containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.45f),
                borderColor = MaterialTheme.colorScheme.primary
            ) {
                Text(strings.comparatorInvariantBanner, style = MaterialTheme.typography.bodySmall)
            }
        }

        // Dual Import Cards: CUSTOM ROM & GSI
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                ImportArchiveCard(
                    title = strings.importCustomRomTitle,
                    report = romReport,
                    onPickZip = { romZipPicker.launch(arrayOf("application/zip", "application/octet-stream", "*/*")) },
                    onLoadLocal = { viewModel.loadLocalSession(isRom = true) },
                    modifier = Modifier
                        .weight(1f)
                        .testTag("import_rom_zip")
                )
                ImportArchiveCard(
                    title = strings.importGsiTitle,
                    report = gsiReport,
                    onPickZip = { gsiZipPicker.launch(arrayOf("application/zip", "application/octet-stream", "*/*")) },
                    onLoadLocal = { viewModel.loadLocalSession(isRom = false) },
                    modifier = Modifier
                        .weight(1f)
                        .testTag("import_gsi_zip")
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

        // Run Comparison + Export Actions
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Button(
                    onClick = { viewModel.runComparison(language) },
                    enabled = romReport != null && gsiReport != null,
                    modifier = Modifier
                        .weight(1f)
                        .heightIn(min = 50.dp)
                        .testTag("btn_run_comparison")
                ) {
                    Icon(Icons.Filled.CompareArrows, contentDescription = strings.btnRunComparison)
                    Spacer(Modifier.width(6.dp))
                    Text(strings.btnRunComparison, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }

                Box {
                    OutlinedButton(
                        onClick = { showExportMenu = true },
                        enabled = comparison != null && !exportState.isExporting,
                        modifier = Modifier
                            .heightIn(min = 50.dp)
                            .testTag("btn_export_comparison")
                    ) {
                        Icon(Icons.Filled.Download, contentDescription = strings.btnExportComparisonReport)
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
                                    viewModel.exportComparison(asHtml = true, language = language, targetUri = null)
                                } else {
                                    htmlExportLauncher.launch("fod_comparison_${comparison?.romSessionId}_vs_${comparison?.gsiSessionId}.html")
                                }
                            }
                        )
                        DropdownMenuItem(
                            text = { Text(strings.btnExportSingleMd) },
                            onClick = {
                                showExportMenu = false
                                if (allFilesGranted) {
                                    viewModel.exportComparison(asHtml = false, language = language, targetUri = null)
                                } else {
                                    mdExportLauncher.launch("fod_comparison_${comparison?.romSessionId}_vs_${comparison?.gsiSessionId}.md")
                                }
                            }
                        )
                    }
                }
            }
        }

        if (exportState.isExporting || exportState.message != null) {
            item {
                TelemetrySectionCard {
                    if (exportState.isExporting) {
                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                    } else {
                        Text(
                            text = "${if (exportState.isError) strings.exportErrorMessage else strings.exportSuccessMessage}: ${exportState.message}",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }
        }

        val comp = comparison
        if (comp == null) {
            item {
                TelemetrySectionCard {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 22.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(Icons.Filled.CompareArrows, contentDescription = null, modifier = Modifier.size(44.dp), tint = MaterialTheme.colorScheme.primary)
                        Text(strings.emptyComparatorTitle, style = MaterialTheme.typography.titleLarge)
                        Text(strings.emptyComparatorBody, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
        } else {
            // Boot / Vendor Parity Banner
            item {
                TelemetrySectionCard(
                    borderColor = if (comp.bootVendorParityVerified) statusColors.confirmed else statusColors.suspect
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Icon(
                            imageVector = if (comp.bootVendorParityVerified) Icons.Filled.Verified else Icons.Filled.Warning,
                            contentDescription = null,
                            tint = if (comp.bootVendorParityVerified) statusColors.confirmed else statusColors.suspect
                        )
                        Text(
                            text = if (comp.bootVendorParityVerified) strings.bootVendorParityOk else strings.bootVendorParityWarn,
                            style = MaterialTheme.typography.titleSmall
                        )
                    }
                    Text(comp.bootVendorParitySummary, style = MaterialTheme.typography.labelSmall)
                }
            }

            // Gemini High Thinking Forensic Synthesis
            item {
                TelemetrySectionCard(borderColor = MaterialTheme.colorScheme.tertiary.copy(alpha = 0.7f)) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        Icon(Icons.Filled.AutoAwesome, contentDescription = null, tint = MaterialTheme.colorScheme.tertiary)
                        Text(strings.aiSynthesisTitle, style = MaterialTheme.typography.titleSmall)
                    }
                    when (aiState) {
                        AiSynthesisState.Idle -> Unit
                        AiSynthesisState.Loading -> {
                            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                                Text("Gemini 4 Carbon · Thinking HIGH...", style = MaterialTheme.typography.bodySmall)
                            }
                        }
                        is AiSynthesisState.Streaming -> {
                            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                            Text((aiState as AiSynthesisState.Streaming).text, style = MaterialTheme.typography.bodyMedium)
                        }
                        is AiSynthesisState.Success -> {
                            Text((aiState as AiSynthesisState.Success).text, style = MaterialTheme.typography.bodyMedium)
                        }
                        is AiSynthesisState.Error -> {
                            Text((aiState as AiSynthesisState.Error).message, color = statusColors.failed, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }

            // 8 Comparative Categories
            item {
                val sections = listOf(
                    strings.compDemonstratedBreaks to comp.demonstratedBreaks.size,
                    strings.compConfigsAndPatches to comp.configAndPatchDiffs.size,
                    strings.compMissingInGsi to comp.missingInGsi.size,
                    strings.compMissingInteractions to comp.missingLiveInteractions.size,
                    strings.compCommonDiffs to comp.commonComponentDiffs.size,
                    strings.compVersionInterfaces to comp.versionAndInterfaceDiffs.size,
                    strings.compIncompatibleLibs to comp.incompatibleLibsAndServices.size,
                    strings.compSystemRemediation to comp.remediationOptions.size
                )
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    sections.forEachIndexed { idx, (label, count) ->
                        FilterChip(
                            selected = activeSection == idx,
                            onClick = { activeSection = idx },
                            label = { Text("$label ($count)") }
                        )
                    }
                }
            }

            if (activeSection == 7) {
                items(comp.remediationOptions, key = { it.id }) { rem ->
                    TelemetrySectionCard {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(rem.title, style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
                            StatusPill(status = rem.status)
                        }
                        Surface(
                            color = if (!rem.requiresFrameworkOrSystemUi) statusColors.confirmedContainer else statusColors.suspectContainer,
                            shape = RoundedCornerShape(6.dp)
                        ) {
                            Text(
                                text = if (!rem.requiresFrameworkOrSystemUi) strings.noFrameworkChangeBadge else strings.frameworkChangeBadge,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                                style = MaterialTheme.typography.labelSmall,
                                color = if (!rem.requiresFrameworkOrSystemUi) statusColors.confirmed else statusColors.suspect,
                                fontWeight = FontWeight.Bold
                            )
                        }
                        Text(rem.description, style = MaterialTheme.typography.bodyMedium)
                        if (rem.supportingEvidence.isNotBlank()) {
                            Text(rem.supportingEvidence, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        Text("Limits: ${rem.limitations}", style = MaterialTheme.typography.bodySmall, color = statusColors.suspect)
                    }
                }
            } else {
                val entries: List<ComparisonEntry> = when (activeSection) {
                    0 -> comp.demonstratedBreaks
                    1 -> comp.configAndPatchDiffs
                    2 -> comp.missingInGsi
                    3 -> comp.missingLiveInteractions
                    4 -> comp.commonComponentDiffs
                    5 -> comp.versionAndInterfaceDiffs
                    else -> comp.incompatibleLibsAndServices
                }
                items(entries) { item ->
                    TelemetrySectionCard {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(item.title, style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
                            StatusPill(status = item.status)
                        }
                        KnowledgeBadge(level = item.knowledgeLevel)
                        Text("ROM: ${item.romDetail}", style = MaterialTheme.typography.labelSmall, color = statusColors.confirmed)
                        Text("GSI: ${item.gsiDetail}", style = MaterialTheme.typography.labelSmall, color = statusColors.failed)
                        HorizontalDivider()
                        Text(item.impact, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}

@Composable
private fun ImportArchiveCard(
    title: String,
    report: FodDiagnosticReport?,
    onPickZip: () -> Unit,
    onLoadLocal: () -> Unit,
    modifier: Modifier = Modifier
) {
    val strings = LocalAppStrings.current
    val statusColors = LocalFodStatusColors.current
    TelemetrySectionCard(
        modifier = modifier,
        borderColor = if (report != null) statusColors.confirmed else MaterialTheme.colorScheme.outline.copy(alpha = 0.6f)
    ) {
        Text(title, style = MaterialTheme.typography.titleSmall)
        if (report != null) {
            Text(
                text = "#${report.sessionId} · ${report.environment.deviceModel}",
                style = MaterialTheme.typography.labelSmall,
                color = statusColors.confirmed,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
            Text(
                text = "${report.components.size} comps · ${report.patches.size} patches",
                style = MaterialTheme.typography.labelSmall
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
