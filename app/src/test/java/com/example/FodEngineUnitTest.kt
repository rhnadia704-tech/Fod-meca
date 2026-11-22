package com.example

import com.example.engine.BaselineProbeResult
import com.example.engine.BinarySourceDecoder
import com.example.engine.DynamicProvenanceInspector
import com.example.engine.ElfDisassembler
import com.example.engine.FodComparatorEngine
import com.example.engine.PatchAndArchitectureAnalyzer
import com.example.engine.PortAnalysisEngine
import com.example.engine.PortZipDeepReader
import com.example.engine.ShellExecutor
import com.example.engine.SystemProbeCollector
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

    private fun buildTestUtf8StringPoolChunk(strings: List<String>): ByteArray {
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
        buf.putInt(strings.size)
        buf.putInt(0)
        buf.putInt(0x100) // UTF8_FLAG
        buf.putInt(stringsStart)
        buf.putInt(0)
        offsets.forEach { buf.putInt(it) }
        buf.put(strData)
        return buf.array()
    }

    @Test
    fun binarySourceDecoder_decodesBinaryXmlToReadablePseudoXml() {
        val pool = buildTestUtf8StringPoolChunk(
            listOf(
                "http://schemas.android.com/apk/res/android",
                "android",
                "manifest",
                "overlay",
                "package",
                "targetPackage",
                "isStatic",
                "priority",
                "com.xiaomi.udfps.rro",
                "com.android.systemui"
            )
        )

        // StartElement "manifest" (package="com.xiaomi.udfps.rro")
        val manifestElem = ByteBuffer.allocate(16 + 20 + 20).order(ByteOrder.LITTLE_ENDIAN).apply {
            putShort(0x0102.toShort())
            putShort(16.toShort())
            putInt(56)
            putInt(1)
            putInt(-1)
            // ext: ns=-1, name=2 ("manifest"), attrStart=20, attrSize=20, attrCount=1
            putInt(-1)
            putInt(2)
            putShort(20.toShort())
            putShort(20.toShort())
            putShort(1.toShort())
            putShort(0.toShort())
            putShort(0.toShort())
            putShort(0.toShort())
            // attr: ns=-1, name=4 ("package"), rawVal=8, size=8,0,type=3,data=8
            putInt(-1)
            putInt(4)
            putInt(8)
            putShort(8.toShort())
            put(0)
            put(0x03)
            putInt(8)
        }.array()

        // StartElement "overlay" (android:targetPackage="com.android.systemui", android:isStatic=true, android:priority=50)
        val overlayElem = ByteBuffer.allocate(16 + 20 + 60).order(ByteOrder.LITTLE_ENDIAN).apply {
            putShort(0x0102.toShort())
            putShort(16.toShort())
            putInt(96)
            putInt(2)
            putInt(-1)
            putInt(-1)
            putInt(3) // "overlay"
            putShort(20.toShort())
            putShort(20.toShort())
            putShort(3.toShort())
            putShort(0.toShort())
            putShort(0.toShort())
            putShort(0.toShort())
            // attr 0: android:targetPackage="com.android.systemui"
            putInt(0)
            putInt(5)
            putInt(9)
            putShort(8.toShort())
            put(0)
            put(0x03)
            putInt(9)
            // attr 1: android:isStatic=true (0x12, data=1)
            putInt(0)
            putInt(6)
            putInt(-1)
            putShort(8.toShort())
            put(0)
            put(0x12)
            putInt(1)
            // attr 2: android:priority=50 (0x10, data=50)
            putInt(0)
            putInt(7)
            putInt(-1)
            putShort(8.toShort())
            put(0)
            put(0x10)
            putInt(50)
        }.array()

        fun endElem(nameIdx: Int): ByteArray = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN).apply {
            putShort(0x0103.toShort())
            putShort(16.toShort())
            putInt(24)
            putInt(3)
            putInt(-1)
            putInt(-1)
            putInt(nameIdx)
        }.array()

        val endOverlay = endElem(3)
        val endManifest = endElem(2)
        val totalSize = 8 + pool.size + manifestElem.size + overlayElem.size + endOverlay.size + endManifest.size
        val xmlBytes = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN).apply {
            putShort(0x0003.toShort()) // RES_XML_TYPE
            putShort(8.toShort())
            putInt(totalSize)
            put(pool)
            put(manifestElem)
            put(overlayElem)
            put(endOverlay)
            put(endManifest)
        }.array()

        val decoded = BinarySourceDecoder.decodeBinaryXmlToPseudoXml(xmlBytes)
        assertTrue(decoded.contains("<manifest package=\"com.xiaomi.udfps.rro\">"))
        assertTrue(decoded.contains("<overlay android:targetPackage=\"com.android.systemui\" android:isStatic=\"true\" android:priority=\"50\" />"))
        assertTrue(decoded.contains("</manifest>"))
    }

    @Test
    fun binarySourceDecoder_decodesArscResourceTableEntries() {
        val globalPool = buildTestUtf8StringPoolChunk(listOf("/sys/class/drm/card0-DSI-1/disp_param"))
        val typePool = buildTestUtf8StringPoolChunk(listOf("bool", "string"))
        val keyPool = buildTestUtf8StringPoolChunk(listOf("config_supportsUdfps", "config_udfps_hbm_sysfs_node"))

        // Type 1 ("bool"): 1 entry -> config_supportsUdfps = true
        val boolEntryBytes = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN).apply {
            putShort(8.toShort()) // size
            putShort(0.toShort()) // flags
            putInt(0) // keyIdx = "config_supportsUdfps"
            putShort(8.toShort())
            put(0)
            put(0x12) // TYPE_INT_BOOLEAN
            putInt(1)
        }.array()
        val boolTypeChunk = ByteBuffer.allocate(24 + 4 + boolEntryBytes.size).order(ByteOrder.LITTLE_ENDIAN).apply {
            putShort(0x0201.toShort()) // RES_TABLE_TYPE_TYPE
            putShort(20.toShort()) // headerSize=20 -> offsets at +20? Let's make headerSize=20 and write 1 offset at +20, entriesStart=24 Wait: keep offsets at 20..24
            // Wait: in ResTable_type, cHeader includes ResTable_config (headerSize=20 puts offsets at 20). Let's align cleanly:
            putInt(24 + boolEntryBytes.size)
            put(1) // typeId = 1 ("bool")
            put(0) // flags
            putShort(0.toShort())
            putInt(1) // entryCount
            putInt(24) // entriesStart = 20 + 4
            putInt(0) // offset[0] = 0
            put(boolEntryBytes)
        }.array().copyOf(24 + boolEntryBytes.size)

        // Type 2 ("string"): 1 entry -> config_udfps_hbm_sysfs_node = globalPool[0]
        val strEntryBytes = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN).apply {
            putShort(8.toShort())
            putShort(0.toShort())
            putInt(1) // keyIdx = "config_udfps_hbm_sysfs_node"
            putShort(8.toShort())
            put(0)
            put(0x03) // TYPE_STRING
            putInt(0) // globalPool[0]
        }.array()
        val strTypeChunk = ByteBuffer.allocate(24 + strEntryBytes.size).order(ByteOrder.LITTLE_ENDIAN).apply {
            putShort(0x0201.toShort())
            putShort(20.toShort())
            putInt(24 + strEntryBytes.size)
            put(2) // typeId = 2 ("string")
            put(0)
            putShort(0.toShort())
            putInt(1)
            putInt(24)
            putInt(0)
            put(strEntryBytes)
        }.array()

        val pkgHeaderSize = 288
        val typeStringsOffset = pkgHeaderSize
        val keyStringsOffset = typeStringsOffset + typePool.size
        val pkgChunkSize = pkgHeaderSize + typePool.size + keyPool.size + boolTypeChunk.size + strTypeChunk.size

        val pkgChunk = ByteBuffer.allocate(pkgChunkSize).order(ByteOrder.LITTLE_ENDIAN).apply {
            putShort(0x0200.toShort()) // RES_TABLE_PACKAGE_TYPE
            putShort(pkgHeaderSize.toShort())
            putInt(pkgChunkSize)
            putInt(0x7F) // id
            val pkgNameBytes = "com.android.systemui.udfps".toByteArray(Charsets.UTF_16LE)
            val nameBuf = ByteArray(256)
            System.arraycopy(pkgNameBytes, 0, nameBuf, 0, pkgNameBytes.size)
            put(nameBuf)
            putInt(typeStringsOffset) // offset 268
            putInt(typePool.size)
            putInt(keyStringsOffset) // offset 276
            putInt(keyPool.size)
            putInt(0) // typeIdOffset
            put(typePool)
            put(keyPool)
            put(boolTypeChunk)
            put(strTypeChunk)
        }.array()

        val tableSize = 12 + globalPool.size + pkgChunk.size
        val arscBytes = ByteBuffer.allocate(tableSize).order(ByteOrder.LITTLE_ENDIAN).apply {
            putShort(0x0002.toShort()) // RES_TABLE_TYPE
            putShort(12.toShort())
            putInt(tableSize)
            putInt(1) // packageCount
            put(globalPool)
            put(pkgChunk)
        }.array()

        val decoded = BinarySourceDecoder.decodeArscResourceEntries(arscBytes)
        assertTrue(decoded.packageNames.contains("com.android.systemui.udfps"))
        assertTrue(decoded.allFodOrConfigEntries.any {
            it.typeName == "bool" && it.keyName == "config_supportsUdfps" && it.valueText == "true"
        })
        assertTrue(decoded.allFodOrConfigEntries.any {
            it.typeName == "string" && it.keyName == "config_udfps_hbm_sysfs_node" && it.valueText == "/sys/class/drm/card0-DSI-1/disp_param"
        })
    }

    @Test
    fun binarySourceDecoder_extractsFodClassesMethodsAndStringsFromDexInApk() {
        fun encodeUleb128(value: Int): ByteArray {
            val out = ByteArrayOutputStream()
            var v = value
            do {
                var b = v and 0x7F
                v = v ushr 7
                if (v != 0) b = b or 0x80
                out.write(b)
            } while (v != 0)
            return out.toByteArray()
        }

        // Strings must be sorted in a valid DEX; our parser indexes directly so order only affects convention.
        val strings = listOf(
            "Lcom/android/systemui/biometrics/UdfpsController;",
            "Lcom/android/systemui/biometrics/UdfpsView;",
            "/sys/class/drm/card0-DSI-1/disp_param",
            "V",
            "onFingerDown"
        )
        // Layout:
        // Header (112 bytes)
        // string_ids (5 * 4 = 20) at 112..132
        // type_ids (3 * 4 = 12) at 132..144 -> string indices 0, 1, 3
        // proto_ids (1 * 12 = 12) at 144..156 -> shortyIdx=3("V"), returnTypeIdx=2("V"), paramsOff=0
        // method_ids (1 * 8 = 8) at 156..164 -> classIdx=0, protoIdx=0, nameIdx=4("onFingerDown")
        // class_defs (1 * 32 = 32) at 164..196 -> classIdx=0, accessFlags=1, superclassIdx=1, ...
        // string data starting at 196
        val strDataBaos = ByteArrayOutputStream()
        val strDataOffsets = IntArray(strings.size)
        val dataBase = 196
        strings.forEachIndexed { idx, s ->
            strDataOffsets[idx] = dataBase + strDataBaos.size()
            val utf8 = s.toByteArray(Charsets.UTF_8)
            strDataBaos.write(encodeUleb128(s.length))
            strDataBaos.write(utf8)
            strDataBaos.write(0)
        }
        val strData = strDataBaos.toByteArray()
        val fileSize = dataBase + strData.size
        val dex = ByteBuffer.allocate(fileSize).order(ByteOrder.LITTLE_ENDIAN).apply {
            put("dex\n035\u0000".toByteArray(Charsets.US_ASCII)) // 0..8
            putInt(0) // checksum 8..12
            put(ByteArray(20)) // sha1 12..32
            putInt(fileSize) // 32
            putInt(112) // header_size 36
            putInt(0x12345678) // endian_tag 40
            putInt(0); putInt(0) // link 44..52
            putInt(0) // map_off 52
            putInt(strings.size); putInt(112) // string_ids 56..64
            putInt(3); putInt(132) // type_ids 64..72
            putInt(1); putInt(144) // proto_ids 72..80
            putInt(0); putInt(0) // field_ids 80..88
            putInt(1); putInt(156) // method_ids 88..96
            putInt(1); putInt(164) // class_defs 96..104
            putInt(strData.size); putInt(dataBase) // data 104..112

            // string_ids @ 112
            strDataOffsets.forEach { putInt(it) }
            // type_ids @ 132
            putInt(0); putInt(1); putInt(3)
            // proto_ids @ 144
            putInt(3); putInt(2); putInt(0)
            // method_ids @ 156
            putShort(0.toShort()); putShort(0.toShort()); putInt(4)
            // class_defs @ 164
            putInt(0) // class_idx
            putInt(1) // access_flags = public
            putInt(1) // superclass_idx
            putInt(0); putInt(0); putInt(0); putInt(0); putInt(0)
            // string data @ 196
            put(strData)
        }.array()

        val apkBaos = ByteArrayOutputStream()
        ZipOutputStream(apkBaos).use { zip ->
            zip.putNextEntry(ZipEntry("classes2.dex"))
            zip.write(dex)
            zip.closeEntry()
        }

        val extracted = BinarySourceDecoder.extractFodDexSourcesFromArchive(
            archiveBytes = apkBaos.toByteArray(),
            archivePath = "/system_ext/priv-app/SystemUI/SystemUI.apk",
            targetHint = "com.android.systemui"
        )
        assertTrue(extracted != null)
        assertTrue(extracted?.matchedClasses?.any { it.contains("UdfpsController") } == true)
        assertTrue(extracted?.matchedMethods?.any { it.contains("onFingerDown") } == true)
        assertTrue(extracted?.matchedStrings?.any { it.contains("/sys/class/drm/card0-DSI-1/disp_param") } == true)
    }

    @Test
    fun contentDrivenOverlayScoring_prefersAutoNamedFodRroOverSpoonOverlayWithoutFodContent() {
        val genericSpoon = OverlayDeepInspection(
            packageName = "com.android.systemui.overlay.spoonoverlay2025",
            targetPackage = "com.android.systemui",
            apkPath = "/product/overlay/SpoonOverlay2025.apk",
            directory = "/product/overlay",
            isEnabled = true,
            isStatic = false,
            priority = 100,
            manifestSummary = listOf("targetPackage=com.android.systemui"),
            fodConfigEntries = emptyList(),
            decodedArscEntries = listOf("color/accent_device_default = #ff3ddc84"),
            pseudoXmlSource = "<overlay targetPackage=\"com.android.systemui\" />"
        )
        val realAutoRro = OverlayDeepInspection(
            packageName = "android.auto_generated_rro_product__",
            targetPackage = "android",
            apkPath = "/product/overlay/framework-res__auto_generated_rro_product.apk",
            directory = "/product/overlay",
            isEnabled = true,
            isStatic = true,
            priority = 1,
            provenInLiveMaps = true,
            lookupWinners = listOf("android:bool/config_supportsUdfps -> apk=/product/overlay/framework-res__auto_generated_rro_product.apk"),
            decodedArscEntries = listOf(
                "ARSC bool/config_supportsUdfps = true",
                "ARSC array/config_biometric_sensors = [0:2:15]"
            ),
            fodConfigEntries = listOf("VALUE bool/config_supportsUdfps = true"),
            pseudoXmlSource = "<overlay targetPackage=\"android\" isStatic=\"true\" />"
        )

        val spoonScore = DynamicProvenanceInspector.computeFodOverlayScore(genericSpoon)
        val realScore = DynamicProvenanceInspector.computeFodOverlayScore(realAutoRro)
        assertTrue("Real FOD RRO score ($realScore) must far exceed empty UI overlay score ($spoonScore)", realScore > spoonScore + 100)

        // Verify PortAnalysisEngine routes generic zero-FOD overlay to sharedNoise/filtered rather than top FOD failure
        val romOverlays = listOf(
            genericSpoon.copy(fodRelevanceScore = spoonScore),
            realAutoRro.copy(fodRelevanceScore = realScore)
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
        val romZip = PortZipDeepReader.readCompleteZipStream(
            ByteArrayInputStream(
                zipFrom(
                    mapOf(
                        "metadata/environment.txt" to "Boot Signature: 4.14.357\nVendor Fingerprint: mustang",
                        "raw/dumpsys_overlay.txt" to "[x] com.android.systemui.overlay.spoonoverlay2025\n[x] android.auto_generated_rro_product__\n",
                        "raw/overlay_deep_inspect.txt" to DynamicProvenanceInspector.serializeOverlayDeepInspect(romOverlays)
                    )
                )
            ),
            "ROM",
            "rom_content.zip"
        )
        val gsiZip = PortZipDeepReader.readCompleteZipStream(
            ByteArrayInputStream(
                zipFrom(
                    mapOf(
                        "metadata/environment.txt" to "Boot Signature: 4.14.357\nVendor Fingerprint: mustang",
                        "raw/dumpsys_overlay.txt" to "[x] org.treble.generic\n"
                    )
                )
            ),
            "GSI",
            "gsi_empty.zip"
        )
        val result = PortAnalysisEngine.analyze(romZip, gsiZip, AppLanguage.FR)
        assertTrue(result.extractableFiles.any { it.title == "android.auto_generated_rro_product__" })
        assertFalse(result.extractableFiles.any { it.title == "com.android.systemui.overlay.spoonoverlay2025" })
        assertTrue(result.sharedNoiseSamples.any { it.title == "com.android.systemui.overlay.spoonoverlay2025" })
    }

    @Test
    fun systemProbeCollector_parsesProcMapsAndComputesEnrollmentDelta() {
        val pidNames = mapOf(1200 to "com.android.systemui", 450 to "vendor.goodix.fp")
        val rawT0 = """
            === PID 1200 ===
            /system_ext/priv-app/SystemUI/SystemUI.apk
            /product/overlay/UdfpsOverlay.apk
            /system/framework/framework.jar
            --- FD 1200 ---
            /dev/binder
            === PID 450 ===
            /vendor/lib64/libgf_hal.so
            --- FD 450 ---
            /dev/goodix_fp
        """.trimIndent()
        val rawT1 = """
            === PID 1200 ===
            /system_ext/priv-app/SystemUI/SystemUI.apk
            /product/overlay/UdfpsOverlay.apk
            /system/framework/framework.jar
            /vendor/overlay/DynamicUdfpsHbm.apk
            --- FD 1200 ---
            /dev/binder
            /sys/class/drm/card0-DSI-1/disp_param
            === PID 450 ===
            /vendor/lib64/libgf_hal.so
            /vendor/lib64/libgf_udfps_algo.so
            --- FD 450 ---
            /dev/goodix_fp
        """.trimIndent()

        val t0 = SystemProbeCollector.parseProcMapsOutput(rawT0, pidNames)
        val t1 = SystemProbeCollector.parseProcMapsOutput(rawT1, pidNames)
        val merged = SystemProbeCollector.mergeProcMapsWithDelta(t0, t1)

        val sysUi = merged.first { it.pid == 1200 }
        assertTrue(sysUi.mappedApks.contains("/product/overlay/UdfpsOverlay.apk"))
        assertTrue(sysUi.enrollmentNewMappedFiles.contains("/vendor/overlay/DynamicUdfpsHbm.apk"))
        assertTrue(sysUi.enrollmentNewFds.contains("/sys/class/drm/card0-DSI-1/disp_param"))

        val hal = merged.first { it.pid == 450 }
        assertTrue(hal.mappedLibs.contains("/vendor/lib64/libgf_hal.so"))
        assertTrue(hal.enrollmentNewMappedFiles.contains("/vendor/lib64/libgf_udfps_algo.so"))
    }
}



