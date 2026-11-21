package com.example

import com.example.engine.ElfDisassembler
import com.example.engine.FodComparatorEngine
import com.example.i18n.AppLanguage
import com.example.model.ComponentCategory
import com.example.model.DetectedPatch
import com.example.model.DiagnosticMode
import com.example.model.DiagnosticSummary
import com.example.model.DiscoveredComponent
import com.example.model.EnvironmentSnapshot
import com.example.model.EvidenceStatus
import com.example.model.FodDiagnosticReport
import com.example.model.KnowledgeLevel
import com.example.model.RawArtifactsBundle
import com.example.storage.StreamingReportExporter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class FodEngineUnitTest {

    @Test
    fun elfDisassembler_handlesNonReadableAndBadMagicGracefully() {
        val denied = ElfDisassembler.analyzeBinary("/vendor/bin/hw/fp", null, "Permission denied")
        assertFalse(denied.isReadable)
        assertEquals("Permission denied", denied.accessError)

        val notElf = ElfDisassembler.analyzeBinary("/vendor/etc/test", "HELLO_WORLD_1234567890".repeat(4).toByteArray(), null)
        assertEquals("NOT_ELF", notElf.architecture)
    }

    @Test
    fun elfDisassembler_parsesMinimalElf64Header() {
        val bytes = ByteArray(128)
        bytes[0] = 0x7F
        bytes[1] = 'E'.code.toByte()
        bytes[2] = 'L'.code.toByte()
        bytes[3] = 'F'.code.toByte()
        bytes[4] = 2 // ELF64
        bytes[5] = 1 // LSB
        // e_machine = 183 (0x00B7) at offset 18
        bytes[18] = 0xB7.toByte()
        bytes[19] = 0x00
        val res = ElfDisassembler.analyzeBinary("/vendor/lib64/libfod.so", bytes, null)
        assertTrue(res.isReadable)
        assertEquals("AArch64 (ARM64)", res.architecture)
    }

    @Test
    fun comparatorEngine_detectsMissingPatchesAndEnforcesNonVendorRemediation() {
        val sharedEnv = EnvironmentSnapshot(
            deviceModel = "TestPhone",
            manufacturer = "Test",
            board = "kona",
            hardware = "qcom",
            androidRelease = "15",
            sdkInt = 35,
            buildFingerprint = "fp",
            buildType = "userdebug",
            isGsiSuspected = false,
            bootSignature = "boot_sha_123",
            vendorFingerprint = "vendor_fp_123",
            selinuxMode = "Enforcing",
            rootRequested = false,
            rootGranted = false,
            storageAllFilesGranted = false,
            biometricHardwareStatus = "BIOMETRIC_SUCCESS",
            displayModesSummary = "1080x2400@120Hz"
        )

        val rom = FodDiagnosticReport(
            sessionId = "rom01",
            mode = DiagnosticMode.ROM_FOD,
            createdAtIso = "2026-11-21T00:00:00Z",
            enrollmentDurationMs = 5000L,
            environment = sharedEnv,
            sessionFlow = emptyList(),
            components = listOf(
                DiscoveredComponent(
                    id = "c1",
                    name = "vendor.fod.overlay",
                    category = ComponentCategory.OVERLAY,
                    version = "ENABLED",
                    interfaceType = "RRO",
                    path = "vendor.fod.overlay",
                    status = EvidenceStatus.CONFIRMED,
                    knowledgeLevel = KnowledgeLevel.FACT
                )
            ),
            dependencyEdges = emptyList(),
            patches = listOf(
                DetectedPatch(
                    id = "p1",
                    name = "persist.vendor.sys.fp.fod.enable",
                    source = "getprop",
                    scope = "Device Prop",
                    target = "persist.vendor.sys.fp.fod.enable",
                    rawValue = "1",
                    status = EvidenceStatus.CONFIRMED,
                    realObservedEffect = "Active",
                    note = ""
                )
            ),
            elfAnalyses = emptyList(),
            findings = emptyList(),
            summary = DiagnosticSummary(
                overallOutcome = "SUCCESS",
                enrollmentObserved = true,
                enrollmentSucceeded = true,
                realSuccessDespiteNoiseNote = "OK",
                firstDemonstratedBreak = "None",
                confirmedCount = 1,
                observedCount = 0,
                suspectCount = 0,
                failedCount = 0,
                unknownCount = 0
            ),
            rawArtifacts = RawArtifactsBundle()
        )

        val gsi = rom.copy(
            sessionId = "gsi01",
            mode = DiagnosticMode.GSI_FOD,
            environment = sharedEnv.copy(isGsiSuspected = true),
            components = emptyList(),
            patches = listOf(
                DetectedPatch(
                    id = "p2",
                    name = "persist.sys.phh.fod.xiaomi",
                    source = "getprop",
                    scope = "GSI / Treble Patch Prop",
                    target = "persist.sys.phh.fod.xiaomi",
                    rawValue = "true",
                    status = EvidenceStatus.CONFIRMED,
                    realObservedEffect = "Did not prevent break",
                    note = ""
                )
            ),
            summary = rom.summary.copy(
                overallOutcome = "FAILED",
                enrollmentSucceeded = false,
                firstDemonstratedBreak = "HBM failed"
            )
        )

        val diff = FodComparatorEngine.compare(rom, gsi, AppLanguage.FR)
        assertTrue(diff.bootVendorParityVerified)
        assertTrue(diff.missingInGsi.any { it.title == "vendor.fod.overlay" })
        assertTrue(diff.configAndPatchDiffs.any { it.title == "persist.vendor.sys.fp.fod.enable" })
        assertTrue(diff.remediationOptions.any { !it.requiresFrameworkOrSystemUi })
    }

    @Test
    fun zipStreamParser_rejectsInvalidArchive() {
        val baos = ByteArrayOutputStream()
        ZipOutputStream(baos).use { z ->
            z.putNextEntry(ZipEntry("other.txt"))
            z.write("abc".toByteArray())
            z.closeEntry()
        }
        var threw = false
        try {
            StreamingReportExporter.parseReportFromZipStream(ByteArrayInputStream(baos.toByteArray()))
        } catch (e: IllegalStateException) {
            threw = true
        }
        assertTrue(threw)
    }
}
