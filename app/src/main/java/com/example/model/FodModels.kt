package com.example.model

import com.squareup.moshi.JsonClass

enum class DiagnosticMode {
    ROM_FOD,
    GSI_FOD
}

enum class EvidenceStatus {
    OBSERVED,
    CONFIRMED,
    FAILED,
    SUSPECT,
    UNKNOWN
}

enum class KnowledgeLevel {
    FACT,
    CORRELATION,
    DEDUCTION,
    HYPOTHESIS
}

enum class ComponentCategory {
    HAL,
    SERVICE,
    LIBRARY,
    INTERFACE,
    SYSFS_NODE,
    OVERLAY,
    PROPERTY,
    PATCH,
    DISPLAY_PIPELINE,
    SELINUX
}

@JsonClass(generateAdapter = true)
data class SessionEvent(
    val id: String,
    val timestamp: String,
    val relativeMs: Long,
    val phase: String,
    val component: String,
    val summary: String,
    val rawEvidence: String,
    val status: EvidenceStatus,
    val knowledgeLevel: KnowledgeLevel,
    val isBenignWarning: Boolean = false,
    val isBlockingFailure: Boolean = false
)

@JsonClass(generateAdapter = true)
data class DiscoveredComponent(
    val id: String,
    val name: String,
    val category: ComponentCategory,
    val version: String,
    val interfaceType: String,
    val path: String,
    val status: EvidenceStatus,
    val knowledgeLevel: KnowledgeLevel,
    val dependencies: List<String> = emptyList(),
    val metadata: Map<String, String> = emptyMap(),
    val accessNote: String? = null
)

@JsonClass(generateAdapter = true)
data class DependencyEdge(
    val fromId: String,
    val toId: String,
    val relation: String,
    val status: EvidenceStatus,
    val note: String
)

@JsonClass(generateAdapter = true)
data class DetectedPatch(
    val id: String,
    val name: String,
    val source: String,
    val scope: String,
    val target: String,
    val rawValue: String,
    val status: EvidenceStatus,
    val realObservedEffect: String,
    val note: String
)

@JsonClass(generateAdapter = true)
data class ElfBinaryAnalysis(
    val path: String,
    val architecture: String,
    val fileSizeBytes: Long,
    val isReadable: Boolean,
    val dtNeeded: List<String> = emptyList(),
    val fodSymbols: List<String> = emptyList(),
    val fodStrings: List<String> = emptyList(),
    val disassemblyPseudoCode: String = "",
    val accessError: String? = null
)

@JsonClass(generateAdapter = true)
data class EnvironmentSnapshot(
    val deviceModel: String,
    val manufacturer: String,
    val board: String,
    val hardware: String,
    val androidRelease: String,
    val sdkInt: Int,
    val buildFingerprint: String,
    val buildType: String,
    val isGsiSuspected: Boolean,
    val gsiIndicators: List<String> = emptyList(),
    val bootSignature: String,
    val vendorFingerprint: String,
    val selinuxMode: String,
    val rootRequested: Boolean,
    val rootGranted: Boolean,
    val storageAllFilesGranted: Boolean,
    val biometricHardwareStatus: String,
    val displayModesSummary: String,
    val accessLimitations: List<String> = emptyList()
)

@JsonClass(generateAdapter = true)
data class OverlayDeepInspection(
    val packageName: String,
    val targetPackage: String = "",
    val apkPath: String = "UNKNOWN",
    val directory: String = "UNKNOWN",
    val isEnabled: Boolean = false,
    val isStatic: Boolean = false,
    val priority: Int = 0,
    val manifestSummary: List<String> = emptyList(),
    val fodConfigEntries: List<String> = emptyList(),
    val rawDumpNote: String = "",
    val fodRelevanceScore: Int = 0,
    val provenInLiveMaps: Boolean = false,
    val lookupWinners: List<String> = emptyList(),
    val pseudoXmlSource: String = "",
    val decodedArscEntries: List<String> = emptyList()
)

@JsonClass(generateAdapter = true)
data class LiveProcessMapRecord(
    val pid: Int,
    val processName: String,
    val mappedApks: List<String> = emptyList(),
    val mappedJarsAndDex: List<String> = emptyList(),
    val mappedLibs: List<String> = emptyList(),
    val openFds: List<String> = emptyList(),
    val matchedFodPaths: List<String> = emptyList(),
    val enrollmentNewMappedFiles: List<String> = emptyList(),
    val enrollmentNewFds: List<String> = emptyList()
)

@JsonClass(generateAdapter = true)
data class DexSourceExtract(
    val archivePath: String,
    val targetHint: String,
    val matchedClasses: List<String> = emptyList(),
    val matchedMethods: List<String> = emptyList(),
    val matchedStrings: List<String> = emptyList(),
    val sourcePseudoSummary: String = ""
)

@JsonClass(generateAdapter = true)
data class FileProvenanceArtifact(
    val id: String,
    val category: String,
    val filePath: String,
    val directory: String,
    val matchedSymbolOrKey: String,
    val importantContents: List<String> = emptyList(),
    val accessNote: String? = null
)

@JsonClass(generateAdapter = true)
data class RawArtifactsBundle(
    val logcatBaseline: String = "",
    val logcatEnrollment: String = "",
    val dumpsysFingerprint: String = "",
    val dumpsysBiometric: String = "",
    val dumpsysSurfaceFlinger: String = "",
    val dumpsysDisplay: String = "",
    val dumpsysOverlay: String = "",
    val lshalOutput: String = "",
    val vintfManifests: String = "",
    val serviceList: String = "",
    val getpropAll: String = "",
    val sysfsFodNodes: String = "",
    val selinuxDenials: String = "",
    val initRcSnippets: String = "",
    val elfDisassemblyFull: String = "",
    val dmesgDelta: String = "",
    val surfaceFlingerLiveDelta: String = "",
    val overlayDeepInspect: String = "",
    val fileProvenanceIndex: String = "",
    val procLiveMaps: String = "",
    val dexSourceExtract: String = ""
)

@JsonClass(generateAdapter = true)
data class FingerDownStep(
    val order: Int,
    val stage: String,
    val status: EvidenceStatus,
    val detail: String,
    val evidence: String = ""
)

@JsonClass(generateAdapter = true)
data class SysfsTransition(
    val nodePath: String,
    val beforeValue: String,
    val liveValues: List<String> = emptyList(),
    val afterValue: String,
    val changed: Boolean
)

@JsonClass(generateAdapter = true)
data class InvestigationFinding(
    val id: String,
    val title: String,
    val detail: String,
    val evidenceSnippet: String,
    val status: EvidenceStatus,
    val knowledgeLevel: KnowledgeLevel,
    val isBenignNoise: Boolean = false,
    val isBlocking: Boolean = false
)

@JsonClass(generateAdapter = true)
data class DiagnosticSummary(
    val overallOutcome: String,
    val enrollmentObserved: Boolean,
    val enrollmentSucceeded: Boolean?,
    val realSuccessDespiteNoiseNote: String,
    val firstDemonstratedBreak: String,
    val confirmedCount: Int,
    val observedCount: Int,
    val suspectCount: Int,
    val failedCount: Int,
    val unknownCount: Int,
    val aiThinkingSynthesis: String = ""
)

@JsonClass(generateAdapter = true)
data class FodDiagnosticReport(
    val sessionId: String,
    val mode: DiagnosticMode,
    val createdAtIso: String,
    val enrollmentDurationMs: Long,
    val environment: EnvironmentSnapshot,
    val sessionFlow: List<SessionEvent>,
    val components: List<DiscoveredComponent>,
    val dependencyEdges: List<DependencyEdge>,
    val patches: List<DetectedPatch>,
    val elfAnalyses: List<ElfBinaryAnalysis>,
    val findings: List<InvestigationFinding>,
    val summary: DiagnosticSummary,
    val rawArtifacts: RawArtifactsBundle,
    val fingerDownChain: List<FingerDownStep> = emptyList(),
    val sysfsTransitions: List<SysfsTransition> = emptyList(),
    val overlayInspections: List<OverlayDeepInspection> = emptyList(),
    val fileProvenance: List<FileProvenanceArtifact> = emptyList(),
    val procLiveMaps: List<LiveProcessMapRecord> = emptyList(),
    val dexSourceExtracts: List<DexSourceExtract> = emptyList()
)

@JsonClass(generateAdapter = true)
data class ComparisonEntry(
    val title: String,
    val romDetail: String,
    val gsiDetail: String,
    val impact: String,
    val status: EvidenceStatus,
    val knowledgeLevel: KnowledgeLevel
)

@JsonClass(generateAdapter = true)
data class RemediationOption(
    val id: String,
    val title: String,
    val layer: String,
    val requiresFrameworkOrSystemUi: Boolean,
    val description: String,
    val supportingEvidence: String,
    val limitations: String,
    val status: EvidenceStatus
)

@JsonClass(generateAdapter = true)
data class ComparisonResult(
    val romSessionId: String,
    val gsiSessionId: String,
    val createdAtIso: String,
    val bootVendorParityVerified: Boolean,
    val bootVendorParitySummary: String,
    val commonComponentDiffs: List<ComparisonEntry>,
    val missingInGsi: List<ComparisonEntry>,
    val versionAndInterfaceDiffs: List<ComparisonEntry>,
    val incompatibleLibsAndServices: List<ComparisonEntry>,
    val configAndPatchDiffs: List<ComparisonEntry>,
    val missingLiveInteractions: List<ComparisonEntry>,
    val demonstratedBreaks: List<ComparisonEntry>,
    val remediationOptions: List<RemediationOption>,
    val aiDeepComparisonMarkdown: String = "",
    val trueGsiBlockers: List<ComparisonEntry> = emptyList(),
    val sharedNonBlockingItems: List<ComparisonEntry> = emptyList()
)
