package com.example

import com.example.engine.BaselineProbeResult
import com.example.engine.DynamicProvenanceInspector
import com.example.engine.ElfDisassembler
import com.example.engine.FodComparatorEngine
import com.example.engine.PatchAndArchitectureAnalyzer
import com.example.engine.PortAnalysisEngine
import com.example.engine.PortZipDeepReader
import com.example.engine.ShellExecutor
import com.example.i18n.AppLanguage
import com.example.model.ComponentCategory
import com.example.model.DetectedPatch
import com.example.model.DiagnosticMode
import com.example.model.DiagnosticSummary
import com.example.model.DiscoveredComponent
import com.example.model.EnvironmentSnapshot
import com.example.model.EvidenceStatus
import com.example.model.FileProvenanceArtifact
import com.example.model.FingerDownStep
import com.example.model.FodDiagnosticReport
import com.example.model.KnowledgeLevel
import com.example.model.OverlayDeepInspection
import com.example.model.RawArtifactsBundle
import com.example.model.SessionEvent
import com.example.model.SysfsTransition
import com.example.storage.StreamingReportExporter
import java.io.BufferedWriter
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.StringWriter
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

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

    @Test
    fun bootParity_handlesOmittedVbmetaDigestGracefully() {
        val romBoot = "fcd0aa8857711b79a04bad47821087912ae83740aa565be3217aefd9f776c38d | 4.14.357-openela-perf-g9678313c01ba"
        val gsiBoot = "4.14.357-openela-perf-g9678313c01ba"
        assertTrue(FodComparatorEngine.areBootSignaturesCompatible(romBoot, gsiBoot))
        assertFalse(
            FodComparatorEngine.areBootSignaturesCompatible(
                "4.14.357-openela-perf-aaa",
                "5.10.100-gki-bbb"
            )
        )
    }

    @Test
    fun portZipAndEngine_readsAllEntriesAndFiltersInactiveOrSharedNoise() {
        fun buildZipBytes(files: Map<String, String>): ByteArray {
            val baos = ByteArrayOutputStream()
            ZipOutputStream(baos).use { z ->
                files.forEach { (name, content) ->
                    z.putNextEntry(ZipEntry(name))
                    z.write(content.toByteArray(Charsets.UTF_8))
                    z.closeEntry()
                }
            }
            return baos.toByteArray()
        }

        val romBytes = buildZipBytes(
            mapOf(
                "metadata/environment.txt" to "Boot Signature: fcd0aa | 4.14.357-openela-perf\nVendor Fingerprint: google/mustang_beta/release-keys",
                "raw/getprop_all.txt" to "[ro.hardware.fp.fod]: [true]\n[ro.build.date.utc]: [1700000001]\n",
                "raw/dumpsys_overlay.txt" to "[x] com.xiaomi.udfps.overlay\n[ ] com.android.systemui.overlay.ambientcue\n",
                "raw/selinux_denials.txt" to "avc: denied { read } for scontext=u:r:system_server:s0 tclass=file\n",
                "raw/lshal.txt" to "android.hardware.biometrics.fingerprint@2.3::IBiometricsFingerprint/default\n",
                "raw/logcat_enrollment.txt" to "onFingerDown id=0\nextCmd cmd=10\nonEnrollResult remaining=14\n"
            )
        )
        val gsiBytes = buildZipBytes(
            mapOf(
                "metadata/environment.txt" to "Boot Signature: 4.14.357-openela-perf\nVendor Fingerprint: google/mustang_beta/release-keys",
                "raw/getprop_all.txt" to "[persist.sys.phh.fod.xiaomi]: [true]\n[ro.build.date.utc]: [1700009999]\n",
                "raw/dumpsys_overlay.txt" to "[x] org.treble.generic\n",
                "raw/selinux_denials.txt" to "avc: denied { read } for scontext=u:r:system_server:s0 tclass=file\navc: denied { call } for scontext=u:r:system_app:s0 tclass=binder\n",
                "raw/lshal.txt" to "android.hardware.biometrics.fingerprint@2.3::IBiometricsFingerprint/default\n",
                "raw/logcat_enrollment.txt" to "UdfpsController: showUdfpsOverlay illumination active\n"
            )
        )

        val romBundle = PortZipDeepReader.readCompleteZipStream(ByteArrayInputStream(romBytes), "ROM", "rom.zip")
        val gsiBundle = PortZipDeepReader.readCompleteZipStream(ByteArrayInputStream(gsiBytes), "GSI", "gsi.zip")
        assertEquals(6, romBundle.totalFiles)
        assertEquals(6, gsiBundle.totalFiles)

        val portResult = PortAnalysisEngine.analyze(romBundle, gsiBundle, AppLanguage.FR)
        assertTrue(portResult.bootVendorParityVerified)
        // Missing FOD property & active RRO overlay & GSI-only AVC denial & missing ROM callbacks detected
        assertTrue(portResult.factualDiffs.any { it.title == "ro.hardware.fp.fod" && it.status == EvidenceStatus.FAILED })
        assertTrue(portResult.factualDiffs.any { it.title == "com.xiaomi.udfps.overlay" && it.status == EvidenceStatus.FAILED })
        assertTrue(portResult.factualDiffs.any { it.category == "SELINUX AVC (GSI-ONLY)" })
        assertTrue(portResult.factualDiffs.any { it.category == "LIVE LOGCAT CALLBACKS" })
        // Inactive ROM overlay & shared AVC denial must NOT appear in factualDiffs, only in sharedNoise
        assertFalse(portResult.factualDiffs.any { it.title == "com.android.systemui.overlay.ambientcue" })
        assertTrue(portResult.sharedNoiseSamples.any { it.title == "com.android.systemui.overlay.ambientcue" })
        assertTrue(portResult.filteredSharedNoiseCount >= 2)
        // Porting solutions ranked cleanly
        assertTrue(portResult.portingSolutions.size >= 3)

        // Single-file MD & HTML exporters include complete sections
        val mdOut = StringWriter()
        BufferedWriter(mdOut).use { bw ->
            StreamingReportExporter.streamPortMarkdown(bw, portResult, romBundle, gsiBundle, AppLanguage.FR)
        }
        val mdStr = mdOut.toString()
        assertTrue(mdStr.contains("com.xiaomi.udfps.overlay"))
        assertTrue(mdStr.contains("[ROM] raw/logcat_enrollment.txt"))

        val htmlOut = StringWriter()
        BufferedWriter(htmlOut).use { bw ->
            StreamingReportExporter.streamPortHtml(bw, portResult, romBundle, gsiBundle, AppLanguage.FR)
        }
        assertTrue(htmlOut.toString().contains("FOD PORTING DOSSIER"))
    }

    @Test
    fun dynamicProvenanceInspector_parsesDumpsysOverlayBlocksAndBinaryApkPools() {
        val rawDump = """
            com.android.systemui.overlay.spoonoverlay2025:0 {
              mPackageName=com.android.systemui.overlay.spoonoverlay2025
              mTargetPackageName=com.android.systemui
              mBaseCodePath=/product/overlay/SpoonOverlay2025/SpoonOverlay2025.apk
              mState=STATE_ENABLED
              mIsEnabled=true
              mIsStatic=false
              mPriority=150
            }
            org.treble.other:0 {
              mPackageName=org.treble.other
              mTargetPackageName=android
              mBaseCodePath=/system_ext/overlay/Other.apk
              mState=STATE_DISABLED
              mPriority=10
            }
        """.trimIndent()

        val parsedDump = DynamicProvenanceInspector.parseDumpsysOverlayBlocks(rawDump)
        val spoon = parsedDump["com.android.systemui.overlay.spoonoverlay2025"]
        assertTrue(spoon != null)
        assertEquals("com.android.systemui", spoon?.targetPackage)
        assertEquals("/product/overlay/SpoonOverlay2025/SpoonOverlay2025.apk", spoon?.baseCodePath)
        assertEquals(150, spoon?.priority)
        assertTrue(spoon?.isEnabled == true)
        assertFalse(parsedDump["org.treble.other"]?.isEnabled ?: true)

        fun buildUtf8StringPoolChunk(strings: List<String>): ByteArray {
            val dataBaos = ByteArrayOutputStream()
            val offsets = IntArray(strings.size)
            strings.forEachIndexed { idx, s ->
                offsets[idx] = dataBaos.size()
                val utf8 = s.toByteArray(Charsets.UTF_8)
                dataBaos.write(s.length and 0x7F)
                dataBaos.write(utf8.size and 0x7F)
                dataBaos.write(utf8)
                dataBaos.write(0)
            }
            while (dataBaos.size() % 4 != 0) dataBaos.write(0)
            val strData = dataBaos.toByteArray()
            val headerSize = 28
            val stringsStart = headerSize + strings.size * 4
            val chunkSize = stringsStart + strData.size
            val buf = ByteBuffer.allocate(chunkSize).order(ByteOrder.LITTLE_ENDIAN)
            buf.putShort(0x0001.toShort()) // RES_STRING_POOL_TYPE
            buf.putShort(headerSize.toShort())
            buf.putInt(chunkSize)
            buf.putInt(strings.size) // stringCount
            buf.putInt(0) // styleCount
            buf.putInt(0x100) // UTF8_FLAG
            buf.putInt(stringsStart)
            buf.putInt(0) // stylesStart
            offsets.forEach { buf.putInt(it) }
            buf.put(strData)
            return buf.array()
        }

        val apkBaos = ByteArrayOutputStream()
        ZipOutputStream(apkBaos).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write(buildUtf8StringPoolChunk(listOf("com.android.systemui.overlay.spoonoverlay2025", "com.android.systemui")))
            zip.closeEntry()

            zip.putNextEntry(ZipEntry("resources.arsc"))
            zip.write(buildUtf8StringPoolChunk(listOf("config_supportsUdfps", "config_udfps_hbm_sysfs_node", "unrelated_color")))
            zip.closeEntry()
        }

        val parsedApk = DynamicProvenanceInspector.parseApkBinaryFodDetails(apkBaos.toByteArray())
        assertEquals("com.android.systemui", parsedApk.inferredTargetPackage)
        assertTrue(parsedApk.fodResourceStrings.any { it == "arsc: config_supportsUdfps" })
        assertTrue(parsedApk.fodResourceStrings.any { it == "arsc: config_udfps_hbm_sysfs_node" })
        assertTrue(parsedApk.discoveredResourceKeys.any { it.second == "config_supportsUdfps" })
        assertFalse(parsedApk.fodResourceStrings.any { it.contains("unrelated_color") })
    }

    @Test
    fun portEngine_stripsDisplayBrightnessNoiseAndBuildsExtractableProvenance() {
        val romOverlays = listOf(
            OverlayDeepInspection(
                packageName = "com.android.systemui.overlay.spoonoverlay2025",
                targetPackage = "com.android.systemui",
                apkPath = "/product/overlay/SpoonOverlay2025/SpoonOverlay2025.apk",
                directory = "/product/overlay/SpoonOverlay2025",
                isEnabled = true,
                isStatic = false,
                priority = 150,
                manifestSummary = listOf("Overrides targetPackage=com.android.systemui"),
                fodConfigEntries = listOf(
                    "VALUE bool/config_supportsUdfps = true",
                    "VALUE string/config_udfps_hbm_sysfs_node = /sys/devices/platform/soc/soc:qcom,dsi-display-primary/fod_ui"
                )
            )
        )
        val romProvenance = listOf(
            FileProvenanceArtifact(
                id = "p_prop",
                category = "PROP_FILE",
                filePath = "/product/etc/build.prop",
                directory = "/product/etc",
                matchedSymbolOrKey = "2 FOD props",
                importantContents = listOf("ro.hardware.fp.fod=true", "persist.sys.fod.hbm=1")
            ),
            FileProvenanceArtifact(
                id = "p_disp",
                category = "DISPLAY_CONFIG",
                filePath = "/product/etc/displayconfig/display_id_0.xml",
                directory = "/product/etc/displayconfig",
                matchedSymbolOrKey = "display_id_0.xml",
                importantContents = listOf("<highBrightnessMode enabled=\"true\">", "<sdrHdrRatioMap>")
            ),
            FileProvenanceArtifact(
                id = "p_selinux",
                category = "SELINUX_POLICY",
                filePath = "/system_ext/etc/selinux/system_ext_fod.cil",
                directory = "/system_ext/etc/selinux",
                matchedSymbolOrKey = "1 rule",
                importantContents = listOf("(allow system_app sysfs_fod (file (read write open)))")
            )
        )

        val romFiles = mapOf(
            "metadata/environment.txt" to "Boot Signature: 4.14.357-openela-perf\nVendor Fingerprint: google/mustang/release-keys",
            "raw/getprop_all.txt" to "[ro.hardware.fp.fod]: [true]\n[persist.sys.fod.hbm]: [1]\n",
            "raw/dumpsys_overlay.txt" to "[x] com.android.systemui.overlay.spoonoverlay2025\n",
            "raw/overlay_deep_inspect.txt" to DynamicProvenanceInspector.serializeOverlayDeepInspect(romOverlays),
            "raw/file_provenance_index.txt" to DynamicProvenanceInspector.serializeFileProvenanceIndex(romProvenance),
            "raw/init_rc_snippets.txt" to "/system_ext/etc/init/init.fod.rc: chmod 0664 /sys/class/drm/card0-DSI-1/disp_param\n",
            "raw/dumpsys_display.txt" to "Display Brightness=5.1148894E-4 | Display SdrBrightness=5.1148894E-4 | DisplayDeviceInfo{\"Ecran\": uniqueId=\"local:1\", supportedColorModes [0, 7, 9], hbmMode=HIGH_BRIGHTNESS_MODE_HDR, address StablePhysical{id=4630947119594951809, port=129}, ManufactureDate{week=27, year=2006}}"
        )
        val gsiFiles = mapOf(
            "metadata/environment.txt" to "Boot Signature: 4.14.357-openela-perf\nVendor Fingerprint: google/mustang/release-keys",
            "raw/getprop_all.txt" to "[persist.sys.phh.fod.xiaomi]: [true]\n",
            "raw/dumpsys_overlay.txt" to "[x] org.treble.generic\n",
            "raw/init_rc_snippets.txt" to "",
            "raw/dumpsys_display.txt" to "Display Brightness=0.029811 | Display SdrBrightness=0.029811 | DisplayDeviceInfo{\"Ecran\": uniqueId=\"local:2\", supportedColorModes [0], address StablePhysical{id=999, port=1}, ManufactureDate{week=1, year=2025}}"
        )

        fun zipFrom(map: Map<String, String>): ByteArray {
            val baos = ByteArrayOutputStream()
            ZipOutputStream(baos).use { z ->
                map.forEach { (name, content) ->
                    z.putNextEntry(ZipEntry(name))
                    z.write(content.toByteArray(Charsets.UTF_8))
                    z.closeEntry()
                }
            }
            return baos.toByteArray()
        }

        val romBundle = PortZipDeepReader.readCompleteZipStream(ByteArrayInputStream(zipFrom(romFiles)), "ROM", "rom_new.zip")
        val gsiBundle = PortZipDeepReader.readCompleteZipStream(ByteArrayInputStream(zipFrom(gsiFiles)), "GSI", "gsi_new.zip")

        val portResult = PortAnalysisEngine.analyze(romBundle, gsiBundle, AppLanguage.FR)

        // Display noise (Brightness floats, StablePhysical, ManufactureDate) MUST NOT pollute factualDiffs
        val allDiffText = portResult.factualDiffs.joinToString("\n") { "${it.title} | ${it.romEvidence} | ${it.gsiEvidence}" }
        assertFalse(allDiffText.contains("5.1148894E-4"))
        assertFalse(allDiffText.contains("StablePhysical"))
        assertFalse(allDiffText.contains("ManufactureDate"))
        // Real display HBM/ColorMode delta IS captured cleanly
        assertTrue(portResult.factualDiffs.any { it.category == "DISPLAY / HBM PIPELINE" && it.romEvidence.contains("hbmMode=HIGH_BRIGHTNESS_MODE_HDR") })

        // Actionable extractable files dossier pinpoints exact paths, directories, and internal contents
        val spoonExtract = portResult.extractableFiles.firstOrNull { it.title == "com.android.systemui.overlay.spoonoverlay2025" }
        assertTrue(spoonExtract != null)
        assertEquals("/product/overlay/SpoonOverlay2025/SpoonOverlay2025.apk", spoonExtract?.romFilePath)
        assertEquals("/product/overlay/SpoonOverlay2025", spoonExtract?.romDirectory)
        assertTrue(spoonExtract?.importantElements?.any { it.contains("config_supportsUdfps") } == true)

        assertTrue(portResult.extractableFiles.any { it.romFilePath == "/product/etc/build.prop" && it.romDirectory == "/product/etc" })
        assertTrue(portResult.extractableFiles.any { it.romFilePath == "/system_ext/etc/init/init.fod.rc" && it.romDirectory == "/system_ext/etc/init" })
        assertTrue(portResult.extractableFiles.any { it.romFilePath == "/product/etc/displayconfig/display_id_0.xml" })
        assertTrue(portResult.extractableFiles.any { it.romFilePath == "/system_ext/etc/selinux/system_ext_fod.cil" })

        val mdOut = StringWriter()
        BufferedWriter(mdOut).use { bw ->
            StreamingReportExporter.streamPortMarkdown(bw, portResult, romBundle, gsiBundle, AppLanguage.FR)
        }
        val mdStr = mdOut.toString()
        assertTrue(mdStr.contains("Fichiers & Mécanismes à extraire du Custom ROM"))
        assertTrue(mdStr.contains("/product/overlay/SpoonOverlay2025/SpoonOverlay2025.apk"))
        assertTrue(mdStr.contains("/product/overlay/SpoonOverlay2025"))
    }

    @Test
    fun comparatorEngine_normalizesDisplayDeviceInfoMetadataWithoutRegexErrors() {
        val env = sampleEnv(isGsi = false)
        val romDisplayComp = DiscoveredComponent(
            id = "disp_0",
            name = "DisplayEngine",
            category = ComponentCategory.DISPLAY_PIPELINE,
            version = "active",
            interfaceType = "DisplayManager",
            path = "/dev/dri",
            status = EvidenceStatus.CONFIRMED,
            knowledgeLevel = KnowledgeLevel.FACT,
            metadata = mapOf(
                "info" to "Brightness=5.1148894E-4 | SdrBrightness=5.1148894E-4 | address StablePhysical{id=4630947119594951809, port=129}, ManufactureDate{week=27, year=2006}, frameRateOverride , supportedColorModes [0, 7, 9]"
            )
        )
        val gsiDisplayComp = romDisplayComp.copy(
            metadata = mapOf(
                "info" to "Brightness=0.029811 | SdrBrightness=0.029811 | address StablePhysical{id=123456, port=1}, ManufactureDate{week=10, year=2025}, frameRateOverride 60.0, supportedColorModes [0, 7, 9]"
            )
        )
        val baseSummary = DiagnosticSummary(
            overallOutcome = "OK",
            enrollmentObserved = true,
            enrollmentSucceeded = true,
            realSuccessDespiteNoiseNote = "OK",
            firstDemonstratedBreak = "None",
            confirmedCount = 1,
            observedCount = 0,
            suspectCount = 0,
            failedCount = 0,
            unknownCount = 0
        )
        val rom = FodDiagnosticReport(
            sessionId = "r1",
            mode = DiagnosticMode.ROM_FOD,
            createdAtIso = "2026-11-22T00:00:00Z",
            enrollmentDurationMs = 4000L,
            environment = env,
            sessionFlow = emptyList(),
            components = listOf(romDisplayComp),
            dependencyEdges = emptyList(),
            patches = emptyList(),
            elfAnalyses = emptyList(),
            findings = emptyList(),
            summary = baseSummary,
            rawArtifacts = RawArtifactsBundle()
        )
        val gsi = rom.copy(
            sessionId = "g1",
            mode = DiagnosticMode.GSI_FOD,
            environment = env.copy(isGsiSuspected = true),
            components = listOf(gsiDisplayComp)
        )

        val result = FodComparatorEngine.compare(rom, gsi, AppLanguage.FR)
        assertTrue(result.bootVendorParityVerified)
        // Differences solely in Brightness / StablePhysical / ManufactureDate / frameRateOverride must normalize to identical!
        assertFalse(result.commonComponentDiffs.any { it.title == "DisplayEngine" })
    }
}


