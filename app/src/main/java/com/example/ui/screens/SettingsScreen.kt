package com.example.ui.screens

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AdminPanelSettings
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.LightMode
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.i18n.AppLanguage
import com.example.i18n.LocalAppStrings
import com.example.storage.StreamingReportExporter
import com.example.ui.components.TelemetrySectionCard
import com.example.ui.theme.LocalFodStatusColors
import com.example.viewmodel.SettingsViewModel

@Composable
fun SettingsScreen(
    viewModel: SettingsViewModel,
    modifier: Modifier = Modifier
) {
    val strings = LocalAppStrings.current
    val statusColors = LocalFodStatusColors.current
    val context = LocalContext.current

    val settings by viewModel.settings.collectAsStateWithLifecycle()
    val rootTest by viewModel.rootTestState.collectAsStateWithLifecycle()
    val allFilesGranted by viewModel.allFilesGranted.collectAsStateWithLifecycle()

    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        viewModel.refreshStoragePermission()
    }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        contentPadding = PaddingValues(top = 12.dp, bottom = 28.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Text(strings.settingsTitle, style = MaterialTheme.typography.headlineSmall)
        }

        // Language Card
        item {
            TelemetrySectionCard {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Icon(Icons.Filled.Language, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                    Text(strings.settingsLanguageTitle, style = MaterialTheme.typography.titleSmall)
                }
                Text(strings.settingsLanguageDesc, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    AppLanguage.entries.forEach { lang ->
                        FilterChip(
                            selected = settings.language == lang,
                            onClick = { viewModel.setLanguage(lang) },
                            label = { Text(lang.displayName) },
                            modifier = Modifier.testTag("lang_${lang.code}")
                        )
                    }
                }
            }
        }

        // System Theme Card
        item {
            val isDark = isSystemInDarkTheme()
            TelemetrySectionCard {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Icon(
                        imageVector = if (isDark) Icons.Filled.DarkMode else Icons.Filled.LightMode,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Text(strings.settingsThemeTitle, style = MaterialTheme.typography.titleSmall)
                }
                Text(strings.settingsThemeAutoDesc, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(
                    text = if (isDark) "Dark / Sombre (Active)" else "Light / Clair (Active)",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary
                )
            }
        }

        // Optional Root (su) Card
        item {
            TelemetrySectionCard {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(Icons.Filled.AdminPanelSettings, contentDescription = null, tint = MaterialTheme.colorScheme.secondary)
                        Text(strings.settingsRootTitle, style = MaterialTheme.typography.titleSmall)
                    }
                    Switch(
                        checked = settings.rootEnabled,
                        onCheckedChange = { viewModel.setRootEnabled(it) },
                        modifier = Modifier.testTag("switch_root_mode")
                    )
                }
                Text(strings.settingsRootDesc, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)

                val statusText = when {
                    !settings.rootEnabled -> strings.rootDisabledLabel
                    rootTest.granted == true -> "${strings.rootGrantedLabel} (${rootTest.detail})"
                    rootTest.granted == false -> "${strings.rootDeniedLabel} (${rootTest.detail})"
                    else -> strings.rootDisabledLabel
                }
                val statusColor = when {
                    !settings.rootEnabled -> MaterialTheme.colorScheme.onSurfaceVariant
                    rootTest.granted == true -> statusColors.confirmed
                    rootTest.granted == false -> statusColors.failed
                    else -> statusColors.observed
                }
                Text(statusText, style = MaterialTheme.typography.labelMedium, color = statusColor)

                OutlinedButton(
                    onClick = { viewModel.testRoot() },
                    enabled = !rootTest.testing,
                    modifier = Modifier
                        .heightIn(min = 48.dp)
                        .testTag("btn_test_root")
                ) {
                    if (rootTest.testing) {
                        CircularProgressIndicator(modifier = Modifier.width(16.dp))
                    } else {
                        Text(strings.btnTestRoot)
                    }
                }
            }
        }

        // Storage Permission Card
        item {
            TelemetrySectionCard {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Icon(Icons.Filled.Folder, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                    Text(strings.settingsStorageTitle, style = MaterialTheme.typography.titleSmall)
                }
                Text(strings.settingsStorageDesc, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(strings.storageSafActive, style = MaterialTheme.typography.labelMedium, color = statusColors.confirmed)
                Text(
                    text = if (allFilesGranted) strings.storageAllFilesGranted else strings.storageAllFilesNotGranted,
                    style = MaterialTheme.typography.labelMedium,
                    color = if (allFilesGranted) statusColors.confirmed else statusColors.suspect
                )
                Text(
                    text = "Direct path: ${StreamingReportExporter.defaultDirectDirectory().absolutePath}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Button(
                    onClick = { openAllFilesAccessSettings(context) },
                    modifier = Modifier
                        .heightIn(min = 48.dp)
                        .testTag("btn_storage_permission")
                ) {
                    Text(strings.btnGrantAllFiles)
                }
            }
        }

        // Non-intrusive Security Guarantee
        item {
            TelemetrySectionCard(borderColor = statusColors.confirmed.copy(alpha = 0.6f)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Icon(Icons.Filled.Security, contentDescription = null, tint = statusColors.confirmed)
                    Text(strings.settingsSecurityNoteTitle, style = MaterialTheme.typography.titleSmall)
                }
                Text(strings.settingsSecurityNoteBody, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

private fun openAllFilesAccessSettings(context: Context) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        val pkgUri = Uri.parse("package:${context.packageName}")
        val specific = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, pkgUri).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        if (specific.resolveActivity(context.packageManager) != null) {
            context.startActivity(specific)
            return
        }
        val general = Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        if (general.resolveActivity(context.packageManager) != null) {
            context.startActivity(general)
            return
        }
    }
    val appDetails = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${context.packageName}")).apply {
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
    context.startActivity(appDetails)
}
