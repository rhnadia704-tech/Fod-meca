package com.example.ui.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.FilterAlt
import androidx.compose.material.icons.filled.Link
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.i18n.LocalAppStrings
import com.example.model.CausalChainLink
import com.example.model.EvidenceStatus
import com.example.ui.theme.LocalFodStatusColors

@Composable
fun CausalChainSection(
    links: List<CausalChainLink>,
    title: String,
    filteredOverlayCount: Int,
    onCopyPath: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    if (links.isEmpty()) return
    val strings = LocalAppStrings.current
    val statusColors = LocalFodStatusColors.current

    TelemetrySectionCard(
        modifier = modifier.testTag("causal_chain_section"),
        borderColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.65f)
    ) {
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
                Icon(
                    imageVector = Icons.Filled.Link,
                    contentDescription = title,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(20.dp)
                )
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.primary
                )
            }
        }

        if (filteredOverlayCount > 0) {
            Surface(
                color = statusColors.confirmedContainer,
                shape = RoundedCornerShape(6.dp),
                border = BorderStroke(1.dp, statusColors.confirmed.copy(alpha = 0.45f))
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Icon(
                        imageVector = Icons.Filled.FilterAlt,
                        contentDescription = strings.filteredOverlaysNotice,
                        tint = statusColors.confirmed,
                        modifier = Modifier.size(14.dp)
                    )
                    Text(
                        text = "$filteredOverlayCount ${strings.filteredOverlaysNotice}",
                        style = MaterialTheme.typography.labelSmall,
                        color = statusColors.confirmed,
                        fontWeight = FontWeight.SemiBold
                    )
                }
            }
        }

        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            links.forEachIndexed { index, link ->
                CausalLinkRow(
                    link = link,
                    isLast = index == links.lastIndex,
                    onCopyPath = onCopyPath
                )
            }
        }
    }
}

@Composable
private fun CausalLinkRow(
    link: CausalChainLink,
    isLast: Boolean,
    onCopyPath: (String) -> Unit
) {
    val strings = LocalAppStrings.current
    val statusColors = LocalFodStatusColors.current
    var expanded by rememberSaveable(link.order, link.layer) {
        mutableStateOf(link.status == EvidenceStatus.FAILED || link.order == 1)
    }

    val nodeColor: Color = when (link.status) {
        EvidenceStatus.CONFIRMED -> statusColors.confirmed
        EvidenceStatus.OBSERVED -> statusColors.observed
        EvidenceStatus.SUSPECT -> statusColors.suspect
        EvidenceStatus.FAILED -> statusColors.failed
        EvidenceStatus.UNKNOWN -> statusColors.unknown
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .height(IntrinsicSize.Min)
            .testTag("causal_link_${link.order}_${link.layer}")
            .clickable { expanded = !expanded }
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        // Timeline vertical rail with numbered node badge
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier.width(26.dp).fillMaxHeight()
        ) {
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .size(24.dp)
                    .clip(CircleShape)
                    .background(nodeColor)
            ) {
                Text(
                    text = link.order.toString(),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onPrimary,
                    fontWeight = FontWeight.Bold
                )
            }
            if (!isLast) {
                Spacer(Modifier.height(2.dp))
                Box(
                    modifier = Modifier
                        .width(2.dp)
                        .weight(1f)
                        .background(nodeColor.copy(alpha = 0.4f))
                )
            }
        }

        // Causal link content card body
        Surface(
            color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
            shape = RoundedCornerShape(10.dp),
            border = BorderStroke(1.dp, nodeColor.copy(alpha = 0.5f)),
            modifier = Modifier.weight(1f)
        ) {
            Column(
                modifier = Modifier.padding(10.dp),
                verticalArrangement = Arrangement.spacedBy(5.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = link.title,
                        style = MaterialTheme.typography.labelLarge,
                        modifier = Modifier.weight(1f)
                    )
                    StatusPill(status = link.status)
                }

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Surface(
                        color = MaterialTheme.colorScheme.primaryContainer,
                        shape = RoundedCornerShape(4.dp)
                    ) {
                        Text(
                            text = link.proofKind,
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onPrimaryContainer,
                            fontWeight = FontWeight.Bold
                        )
                    }
                    Text(
                        text = link.componentName,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "${link.sourceFile} (${link.sourceDirectory})",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.weight(1f),
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis
                    )
                    if (link.sourceFile.startsWith("/")) {
                        IconButton(
                            onClick = { onCopyPath(link.sourceFile) },
                            modifier = Modifier.size(48.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Filled.ContentCopy,
                                contentDescription = strings.portCopyPathLabel,
                                modifier = Modifier.size(16.dp)
                            )
                        }
                    }
                    Icon(
                        imageVector = if (expanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp)
                    )
                }

                if (link.breakExplanation.isNotBlank()) {
                    Text(
                        text = link.breakExplanation,
                        style = MaterialTheme.typography.bodySmall,
                        color = if (link.status == EvidenceStatus.FAILED) statusColors.failed else statusColors.suspect,
                        fontWeight = FontWeight.Medium
                    )
                }

                AnimatedVisibility(visible = expanded) {
                    Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
                        HorizontalDivider(modifier = Modifier.padding(vertical = 2.dp))
                        if (link.referencedResourceKeys.isNotEmpty()) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .horizontalScroll(rememberScrollState()),
                                horizontalArrangement = Arrangement.spacedBy(5.dp)
                            ) {
                                link.referencedResourceKeys.take(8).forEach { key ->
                                    Surface(
                                        color = MaterialTheme.colorScheme.secondaryContainer,
                                        shape = RoundedCornerShape(4.dp)
                                    ) {
                                        Text(
                                            text = key,
                                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                            style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                                            color = MaterialTheme.colorScheme.onSecondaryContainer
                                        )
                                    }
                                }
                            }
                        }
                        if (link.codeExcerpt.isNotBlank()) {
                            Surface(
                                color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.75f),
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text(
                                    text = link.codeExcerpt,
                                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                                    modifier = Modifier.padding(8.dp)
                                )
                            }
                        }
                        if (link.liveRuntimeEvidence.isNotBlank()) {
                            Surface(
                                color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.45f),
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text(
                                    text = link.liveRuntimeEvidence,
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
}

@Composable
fun PortCausalComparisonSection(
    romChain: List<CausalChainLink>,
    gsiChain: List<CausalChainLink>,
    breakSummary: String,
    filteredNonFodOverlayCount: Int,
    modifier: Modifier = Modifier
) {
    if (romChain.isEmpty()) return
    val strings = LocalAppStrings.current
    val statusColors = LocalFodStatusColors.current

    TelemetrySectionCard(
        modifier = modifier.testTag("port_causal_comparison_section"),
        borderColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.7f)
    ) {
        Text(
            text = strings.portCausalDeltaTitle,
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.primary
        )
        if (filteredNonFodOverlayCount > 0) {
            Text(
                text = "$filteredNonFodOverlayCount ${strings.filteredOverlaysNotice}",
                style = MaterialTheme.typography.labelSmall,
                color = statusColors.confirmed
            )
        }
        if (breakSummary.isNotBlank()) {
            Surface(
                color = statusColors.failedContainer,
                shape = RoundedCornerShape(8.dp),
                border = BorderStroke(1.dp, statusColors.failed.copy(alpha = 0.5f)),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = breakSummary,
                    style = MaterialTheme.typography.bodySmall,
                    color = statusColors.failed,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.padding(8.dp)
                )
            }
        }
        romChain.forEachIndexed { idx, r ->
            val g = gsiChain.getOrNull(idx)
            HorizontalDivider(modifier = Modifier.padding(vertical = 3.dp))
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    text = r.title,
                    style = MaterialTheme.typography.labelLarge
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("ROM:", style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold)
                        StatusPill(status = r.status)
                    }
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("GSI:", style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold)
                        StatusPill(status = g?.status ?: EvidenceStatus.UNKNOWN)
                    }
                }
                Text(
                    text = "ROM: ${r.sourceFile} | GSI: ${g?.sourceFile ?: "ABSENT"}",
                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                if (g != null && g.breakExplanation.isNotBlank()) {
                    Text(
                        text = g.breakExplanation,
                        style = MaterialTheme.typography.labelSmall,
                        color = statusColors.failed
                    )
                }
            }
        }
    }
}
