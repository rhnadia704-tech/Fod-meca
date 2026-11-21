package com.example.model

enum class PortingTier(val order: Int) {
    PROPS_PHH_TREBLE(1),
    RRO_INIT_SELINUX_SYSTEM(2),
    SYSTEMUI_UDFPS(3),
    FRAMEWORK_BIOMETRIC(4)
}

data class ZipEntryDetail(
    val path: String,
    val sizeBytes: Long,
    val lineCount: Int,
    val truncatedInMemory: Boolean = false
)

data class RawZipArchiveBundle(
    val archiveLabel: String,
    val sourceName: String,
    val report: FodDiagnosticReport?,
    val entries: List<ZipEntryDetail>,
    val rawFiles: Map<String, String>
) {
    val totalBytes: Long get() = entries.sumOf { it.sizeBytes }
    val totalFiles: Int get() = entries.size
}

data class PortFileDiffItem(
    val id: String,
    val sourceFile: String,
    val category: String,
    val title: String,
    val romEvidence: String,
    val gsiEvidence: String,
    val impact: String,
    val status: EvidenceStatus,
    val knowledgeLevel: KnowledgeLevel
)

data class PortingCandidateSolution(
    val id: String,
    val tier: PortingTier,
    val rank: Int,
    val title: String,
    val layer: String,
    val requiresFrameworkOrSystemUi: Boolean,
    val confidencePercent: Int,
    val whyItApplies: String,
    val exactSourcesInZip: List<String>,
    val concreteActionSteps: List<String>,
    val limitations: String
)

data class PortAnalysisResult(
    val createdAtIso: String,
    val romSourceName: String,
    val gsiSourceName: String,
    val romFilesRead: Int,
    val gsiFilesRead: Int,
    val romTotalBytes: Long,
    val gsiTotalBytes: Long,
    val bootVendorParityVerified: Boolean,
    val bootVendorParitySummary: String,
    val factualRootCauseVerdict: String,
    val factualDiffs: List<PortFileDiffItem>,
    val filteredSharedNoiseCount: Int,
    val sharedNoiseSamples: List<PortFileDiffItem>,
    val portingSolutions: List<PortingCandidateSolution>,
    val aiProviderUsed: String = "",
    val aiFactualSynthesis: String = ""
)
