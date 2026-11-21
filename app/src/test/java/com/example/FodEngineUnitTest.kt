package com.example

import com.example.engine.BaselineProbeResult
import com.example.engine.ElfDisassembler
import com.example.engine.FodComparatorEngine
import com.example.engine.PatchAndArchitectureAnalyzer
import com.example.engine.ShellExecutor
import com.example.i18n.AppLanguage
import com.example.model.ComponentCategory
import com.example.model.DetectedPatch
import com.example.model.DiagnosticMode
import com.example.model.DiagnosticSummary
import com.example.model.DiscoveredComponent
import com.example.model.EnvironmentSnapshot
import com.example.model.EvidenceStatus
import com.example.model.FingerDownStep
import com.example.model.FodDiagnosticReport
import com.example.model.KnowledgeLevel
import com.example.model.RawArtifactsBundle
import com.example.model.SessionEvent
import com.example.model.SysfsTransition
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

    private fun sampleEnv(isGsi: Boolean = false) = EnvironmentSnapshot(
        deviceModel = "Xiaomi Mi Note 10",
        manufacturer = "Xiaomi",
        board = "tucana",
        hardware = "qcom",
        androidRelease = "17",
        sdkInt = 36,
        buildFingerprint = "fp",
        buildType = "userdebug",
        isGsiSuspected = isGsi,
        bootSignature = "boot_sha_123",
        vendorFingerprint = "vendor_fp_123",
        selinuxMode = "Enforcing",
        rootRequested = true,
        rootGranted = true,
        storageAllFilesGranted = false,
        biometricHardwareStatus = "BIOMETRIC_SUCCESS",
        displayModesSummary = "1080x2340@60Hz"
    )

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
        bytes[18] = 0xB7.toByte()
        bytes[19] = 0x00
        val res = ElfDisassembler.analyzeBinary("/vendor/lib64/libfod.so", bytes, null)
        assertTrue(res.isReadable)
        assertEquals("AArch64 (ARM64)", res.architecture)
    }

    @Test
    fun silentHalStall_detectedWhenFodUiActivatesWithoutHalCallback() {
        val baseline = BaselineProbeResult(
            environment = sampleEnv(isGsi = true),
            getpropAll = "[persist.sys.phh.fod.xiaomi]: [true]\n",
            dumpsysFingerprint = "udfps sensorLocation=[540,1920,90]",
            dumpsysBiometric = "",
            dumpsysSurfaceFlinger = "",
            dumpsysDisplay = "",
            dumpsysOverlay = "",
            lshalOutput = "android.hardware.biometrics.fingerprint@2.3::IBiometricsFingerprint/default",
            vintfManifests = "",
            serviceList = "",
            sysfsFodNodes = "=== /sys/class/drm/card0-DSI-1/fod_status ===\n0\n",
            selinuxDenials = "",
            initRcSnippets = "",
            discoveredBinaryPaths = emptyList(),
            logcatBaseline = "",
            installedOverlayPackages = emptyList()
        )

        val liveLogs = """
            11-21 17:10:01.100  1200  1300 I BiometricService: startPreparedClient FingerprintEnrollClient
            11-21 17:10:02.200  1500  1500 D UdfpsController: showUdfpsOverlay illumination active
        """.trimIndent()

        val report = PatchAndArchitectureAnalyzer.buildReport(
            mode = DiagnosticMode.GSI_FOD,
            baseline = baseline,
            liveLogcat = liveLogs,
            elfAnalyses = emptyList(),
            enrollmentDurationMs = 7000L,
            language = AppLanguage.FR,
            dmesgDelta = "NO_NEW_FOD_DMESG_EVENTS",
            surfaceFlingerLiveDelta = "UdfpsOverlay#12",
            sysfsTransitions = listOf(
                SysfsTransition(
                    nodePath = "/sys/class/drm/card0-DSI-1/fod_status",
                    beforeValue = "0",
                    liveValues = listOf("0"),
                    afterValue = "0",
                    changed = false
                )
            )
        )

        assertEquals(false, report.summary.enrollmentSucceeded)
        assertTrue(report.summary.overallOutcome.contains("BLOCAGE SILENCIEUX"))
        assertTrue(report.sessionFlow.any { it.id == "evt_silent_hal_stall" && it.isBlockingFailure })
        assertTrue(report.fingerDownChain.any { it.order == 5 && it.status == EvidenceStatus.FAILED })
    }

    @Test
    fun comparatorEngine_isolatesTrueGsiBlockersAndFiltersSharedNoise() {
        val sharedEnv = sampleEnv(isGsi = false)

        val sharedMissingComp = DiscoveredComponent(
            id = "c_shared_unknown",
            name = "OptionalSharedBlob",
            category = ComponentCategory.LIBRARY,
            version = "UNKNOWN",
            interfaceType = "ELF",
            path = "/vendor/lib64/optional.so",
            status = EvidenceStatus.UNKNOWN,
            knowledgeLevel = KnowledgeLevel.FACT,
            accessNote = "Missing on both"
        )
        val sharedBenignEvt = SessionEvent(
            id = "evt_shared_warn",
            timestamp = "12:00:00",
            relativeMs = 10L,
            phase = "BIOMETRIC_SVC",
            component = "VendorStub",
            summary = "Property persist.vendor.dummy not found",
            rawEvidence = "W VendorStub: Property persist.vendor.dummy not found",
            status = EvidenceStatus.SUSPECT,
            knowledgeLevel = KnowledgeLevel.FACT,
            isBenignWarning = true
        )

        val rom = FodDiagnosticReport(
            sessionId = "rom01",
            mode = DiagnosticMode.ROM_FOD,
            createdAtIso = "2026-11-21T00:00:00Z",
            enrollmentDurationMs = 5000L,
            environment = sharedEnv.copy(accessLimitations = listOf("Optional probe XYZ denied")),
            sessionFlow = listOf(sharedBenignEvt),
            components = listOf(
                sharedMissingComp,
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
                overallOutcome = "SUCCÈS D'ENREGISTREMENT OBSERVÉ",
                enrollmentObserved = true,
                enrollmentSucceeded = true,
                realSuccessDespiteNoiseNote = "OK",
                firstDemonstratedBreak = "None",
                confirmedCount = 1,
                observedCount = 0,
                suspectCount = 1,
                failedCount = 0,
                unknownCount = 1
            ),
            rawArtifacts = RawArtifactsBundle(),
            fingerDownChain = listOf(
                FingerDownStep(3, "3. HBM / Sysfs", EvidenceStatus.CONFIRMED, "disp_param transitioned 0 -> 1"),
                FingerDownStep(5, "5. HAL Callbacks", EvidenceStatus.CONFIRMED, "onEnrollResult seen")
            ),
            sysfsTransitions = listOf(
                SysfsTransition("/sys/class/drm/card0-DSI-1/fod_status", "0", listOf("1"), "0", changed = true)
            )
        )

        val gsi = rom.copy(
            sessionId = "gsi01",
            mode = DiagnosticMode.GSI_FOD,
            environment = sharedEnv.copy(isGsiSuspected = true, accessLimitations = listOf("Optional probe XYZ denied")),
            sessionFlow = listOf(sharedBenignEvt),
            components = listOf(sharedMissingComp),
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
                overallOutcome = "BLOCAGE SILENCIEUX DÉTECTÉ",
                enrollmentSucceeded = false,
                firstDemonstratedBreak = "Silent HAL stall"
            ),
            fingerDownChain = listOf(
                FingerDownStep(3, "3. HBM / Sysfs", EvidenceStatus.SUSPECT, "Zero sysfs transitions"),
                FingerDownStep(5, "5. HAL Callbacks", EvidenceStatus.FAILED, "SILENT HAL STALL")
            ),
            sysfsTransitions = listOf(
                SysfsTransition("/sys/class/drm/card0-DSI-1/fod_status", "0", listOf("0"), "0", changed = false)
            )
        )

        val diff = FodComparatorEngine.compare(rom, gsi, AppLanguage.FR)
        assertTrue(diff.bootVendorParityVerified)
        assertTrue(diff.trueGsiBlockers.any { it.title.contains("fod_status") })
        assertTrue(diff.trueGsiBlockers.any { it.title.contains("5. HAL Callbacks") })
        assertFalse(diff.trueGsiBlockers.any { it.title == "OptionalSharedBlob" })
        assertTrue(diff.sharedNonBlockingItems.any { it.title == "OptionalSharedBlob" })
        assertTrue(diff.sharedNonBlockingItems.any { it.title.contains("VendorStub") })
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

    @Test
    fun shellExecutor_allowsDrmPathAndBlocksMutatingCommands() {
        // Must allow paths ending in "drm " or properties containing "flash"
        ShellExecutor.validateReadOnly(
            "find /sys/class/drm /sys/devices/virtual/touch -maxdepth 4 -iname '*fod*' 2>/dev/null | head -n 50"
        )
        ShellExecutor.validateReadOnly("getprop | grep -iE 'fod|flashlight'")

        val blocked = listOf(
            "rm -rf /data/local/tmp/x",
            "ls /sys/class/drm; rm /tmp/a",
            "dmesg | tee /sdcard/out.txt",
            "setprop persist.sys.fod 1",
            "cat /proc/cpuinfo > /sdcard/x.txt"
        )
        blocked.forEach { cmd ->
            var didThrow = false
            try {
                ShellExecutor.validateReadOnly(cmd)
            } catch (_: SecurityException) {
                didThrow = true
            }
            assertTrue("Command should have been blocked: $cmd", didThrow)
        }
    }
}
