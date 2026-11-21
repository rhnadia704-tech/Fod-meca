package com.example.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.HelpOutline
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.text.TextMeasurer
import androidx.compose.ui.text.drawText
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.i18n.LocalAppStrings
import com.example.model.ComponentCategory
import com.example.model.DependencyEdge
import com.example.model.DiscoveredComponent
import com.example.model.EvidenceStatus
import com.example.model.KnowledgeLevel
import com.example.ui.theme.LocalFodStatusColors
import kotlin.math.hypot

@Composable
fun StatusPill(
    status: EvidenceStatus,
    modifier: Modifier = Modifier
) {
    val colors = LocalFodStatusColors.current
    val strings = LocalAppStrings.current
    val (fg, bg, icon, label) = when (status) {
        EvidenceStatus.CONFIRMED -> Quad(colors.confirmed, colors.confirmedContainer, Icons.Filled.CheckCircle, strings.statusConfirmed)
        EvidenceStatus.OBSERVED -> Quad(colors.observed, colors.observedContainer, Icons.Filled.Visibility, strings.statusObserved)
        EvidenceStatus.SUSPECT -> Quad(colors.suspect, colors.suspectContainer, Icons.Filled.Warning, strings.statusSuspect)
        EvidenceStatus.FAILED -> Quad(colors.failed, colors.failedContainer, Icons.Filled.Error, strings.statusFailed)
        EvidenceStatus.UNKNOWN -> Quad(colors.unknown, colors.unknownContainer, Icons.Filled.HelpOutline, strings.statusUnknown)
    }
    Surface(
        modifier = modifier,
        color = bg,
        shape = RoundedCornerShape(6.dp),
        border = BorderStroke(1.dp, fg.copy(alpha = 0.45f))
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Icon(
                imageVector = icon,
                contentDescription = label,
                tint = fg,
                modifier = Modifier.size(13.dp)
            )
            Text(
                text = label,
                style = MaterialTheme.typography.labelMedium,
                color = fg,
                fontWeight = FontWeight.Bold
            )
        }
    }
}

@Composable
fun KnowledgeBadge(
    level: KnowledgeLevel,
    modifier: Modifier = Modifier
) {
    val strings = LocalAppStrings.current
    val label = when (level) {
        KnowledgeLevel.FACT -> strings.levelFact
        KnowledgeLevel.CORRELATION -> strings.levelCorrelation
        KnowledgeLevel.DEDUCTION -> strings.levelDeduction
        KnowledgeLevel.HYPOTHESIS -> strings.levelHypothesis
    }
    val tint = when (level) {
        KnowledgeLevel.FACT -> MaterialTheme.colorScheme.secondary
        KnowledgeLevel.CORRELATION -> MaterialTheme.colorScheme.primary
        KnowledgeLevel.DEDUCTION -> MaterialTheme.colorScheme.tertiary
        KnowledgeLevel.HYPOTHESIS -> LocalFodStatusColors.current.suspect
    }
    Surface(
        modifier = modifier,
        color = tint.copy(alpha = 0.14f),
        shape = RoundedCornerShape(5.dp),
        border = BorderStroke(1.dp, tint.copy(alpha = 0.4f))
    ) {
        Text(
            text = label,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
            style = MaterialTheme.typography.labelSmall,
            color = tint,
            fontWeight = FontWeight.SemiBold
        )
    }
}

@Composable
fun TelemetrySectionCard(
    modifier: Modifier = Modifier,
    containerColor: Color = MaterialTheme.colorScheme.surface,
    borderColor: Color = MaterialTheme.colorScheme.outline.copy(alpha = 0.6f),
    content: @Composable ColumnScope.() -> Unit
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.medium,
        colors = CardDefaults.cardColors(containerColor = containerColor),
        border = BorderStroke(1.dp, borderColor),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
            content = content
        )
    }
}

private data class GraphNodePosition(
    val component: DiscoveredComponent,
    val center: Offset
)

@Composable
fun InteractiveDependencyGraph(
    components: List<DiscoveredComponent>,
    edges: List<DependencyEdge>,
    modifier: Modifier = Modifier
) {
    val statusColors = LocalFodStatusColors.current
    val strings = LocalAppStrings.current
    val textMeasurer: TextMeasurer = rememberTextMeasurer()
    var selectedNode by remember(components) { mutableStateOf<DiscoveredComponent?>(components.firstOrNull()) }

    val graphNodes = remember(components) {
        val prioritized = components.filter {
            it.category in listOf(
                ComponentCategory.SERVICE,
                ComponentCategory.DISPLAY_PIPELINE,
                ComponentCategory.HAL,
                ComponentCategory.LIBRARY,
                ComponentCategory.SYSFS_NODE,
                ComponentCategory.OVERLAY,
                ComponentCategory.PATCH
            )
        }.take(16)
        prioritized
    }

    val outlineColor = MaterialTheme.colorScheme.outline
    val surfaceElevated = MaterialTheme.colorScheme.surfaceVariant
    val labelStyle = MaterialTheme.typography.labelSmall.copy(
        color = MaterialTheme.colorScheme.onSurface,
        fontSize = 10.sp
    )

    var lastLayout by remember { mutableStateOf<List<GraphNodePosition>>(emptyList()) }

    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Text(
            text = strings.tapNodeHint,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(340.dp)
                .background(MaterialTheme.colorScheme.surface, MaterialTheme.shapes.medium)
                .pointerInput(graphNodes) {
                    detectTapGestures { tap ->
                        val hit = lastLayout.minByOrNull { hypot(it.center.x - tap.x, it.center.y - tap.y) }
                        if (hit != null && hypot(hit.center.x - tap.x, hit.center.y - tap.y) < 120f) {
                            selectedNode = hit.component
                        }
                    }
                }
        ) {
            Canvas(modifier = Modifier.matchParentSize()) {
                val w = size.width
                val h = size.height
                val col0 = graphNodes.filter {
                    it.category == ComponentCategory.SERVICE || it.category == ComponentCategory.DISPLAY_PIPELINE ||
                        it.category == ComponentCategory.OVERLAY || it.category == ComponentCategory.PATCH
                }
                val col1 = graphNodes.filter { it.category == ComponentCategory.HAL }
                val col2 = graphNodes.filter {
                    it.category == ComponentCategory.LIBRARY || it.category == ComponentCategory.SYSFS_NODE
                }

                val columns = listOf(col0, col1, col2).filter { it.isNotEmpty() }
                val positions = mutableListOf<GraphNodePosition>()
                columns.forEachIndexed { colIdx, list ->
                    val x = if (columns.size == 1) w / 2f else (w * (0.18f + colIdx * 0.32f))
                    val stepY = h / (list.size + 1).toFloat()
                    list.forEachIndexed { rowIdx, comp ->
                        positions += GraphNodePosition(comp, Offset(x, stepY * (rowIdx + 1)))
                    }
                }
                lastLayout = positions
                val posMap = positions.associateBy { it.component.id }

                // Draw edges
                edges.forEach { edge ->
                    val from = posMap[edge.fromId]?.center
                    val to = posMap[edge.toId]?.center
                    if (from != null && to != null) {
                        val edgeColor = when (edge.status) {
                            EvidenceStatus.CONFIRMED -> statusColors.confirmed
                            EvidenceStatus.OBSERVED -> statusColors.observed
                            EvidenceStatus.SUSPECT -> statusColors.suspect
                            EvidenceStatus.FAILED -> statusColors.failed
                            EvidenceStatus.UNKNOWN -> statusColors.unknown
                        }
                        val dash = if (edge.status == EvidenceStatus.UNKNOWN || edge.status == EvidenceStatus.FAILED) {
                            PathEffect.dashPathEffect(floatArrayOf(12f, 8f))
                        } else null
                        drawLine(
                            color = edgeColor.copy(alpha = 0.78f),
                            start = from,
                            end = to,
                            strokeWidth = 3.5f,
                            pathEffect = dash
                        )
                    }
                }

                // Draw nodes
                positions.forEach { node ->
                    val comp = node.component
                    val isSelected = selectedNode?.id == comp.id
                    val nodeColor = when (comp.status) {
                        EvidenceStatus.CONFIRMED -> statusColors.confirmed
                        EvidenceStatus.OBSERVED -> statusColors.observed
                        EvidenceStatus.SUSPECT -> statusColors.suspect
                        EvidenceStatus.FAILED -> statusColors.failed
                        EvidenceStatus.UNKNOWN -> statusColors.unknown
                    }
                    val boxW = 190f
                    val boxH = 54f
                    val topLeft = Offset(node.center.x - boxW / 2f, node.center.y - boxH / 2f)

                    drawRoundRect(
                        color = surfaceElevated,
                        topLeft = topLeft,
                        size = Size(boxW, boxH),
                        cornerRadius = CornerRadius(14f, 14f)
                    )
                    drawRoundRect(
                        color = if (isSelected) nodeColor else outlineColor,
                        topLeft = topLeft,
                        size = Size(boxW, boxH),
                        cornerRadius = CornerRadius(14f, 14f),
                        style = androidx.compose.ui.graphics.drawscope.Stroke(width = if (isSelected) 4.5f else 2f)
                    )
                    drawCircle(
                        color = nodeColor,
                        radius = 7f,
                        center = Offset(topLeft.x + 16f, node.center.y)
                    )
                    val shortName = comp.name.substringAfterLast('.').take(20)
                    val measured = textMeasurer.measure(shortName, style = labelStyle)
                    drawText(
                        textLayoutResult = measured,
                        topLeft = Offset(
                            topLeft.x + 28f,
                            node.center.y - measured.size.height / 2f
                        )
                    )
                }
            }
        }

        selectedNode?.let { node ->
            TelemetrySectionCard {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = node.name,
                        style = MaterialTheme.typography.titleSmall,
                        modifier = Modifier.weight(1f),
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis
                    )
                    StatusPill(status = node.status)
                }
                Text(
                    text = "${node.category} · ${node.interfaceType} · ${node.version}",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary
                )
                Text(
                    text = node.path,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                if (node.accessNote != null) {
                    Text(
                        text = node.accessNote,
                        style = MaterialTheme.typography.bodySmall,
                        color = statusColors.suspect
                    )
                }
                val relatedEdges = edges.filter { it.fromId == node.id || it.toId == node.id }
                if (relatedEdges.isNotEmpty()) {
                    Spacer(Modifier.height(4.dp))
                    relatedEdges.forEach { e ->
                        Text(
                            text = "• [${e.status}] ${e.relation}: ${e.note}",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }
        }
    }
}

private data class Quad<A, B, C, D>(val first: A, val second: B, val third: C, val fourth: D)
