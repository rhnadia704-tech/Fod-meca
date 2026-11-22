package com.example.engine

import com.example.i18n.AppLanguage
import com.example.model.ComponentCategory
import com.example.model.DependencyEdge
import com.example.model.DetectedPatch
import com.example.model.DiagnosticMode
import com.example.model.DiagnosticSummary
import com.example.model.DiscoveredComponent
import com.example.model.ElfBinaryAnalysis
import com.example.model.EvidenceStatus
import com.example.model.FingerDownStep
import com.example.model.FodDiagnosticReport
import com.example.model.InvestigationFinding
import com.example.model.KnowledgeLevel
import com.example.model.LiveProcessMapRecord
import com.example.model.RawArtifactsBundle
import com.example.model.SessionEvent
import com.example.model.SysfsTransition
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

object PatchAndArchitectureAnalyzer {

    private val patchPropRegex = Regex(
        "^(persist\\.sys\\.phh\\.|persist\\.sys\\.treble\\.|ro\\.vendor\\.fingerprint\\.|persist\\.vendor\\..*(fp|fod|udfps|hbm|bio)|ro\\.hardware\\.fp|vendor\\.fingerprint\\.|sys\\.fod\\.|persist\\.sys\\.fod|ro\\.oplus\\.fod|ro\\.miui\\.fod|ro\\.boot\\.fp).*",
        RegexOption.IGNORE_CASE
    )

    private val liveLogFilterRegex = Regex(
        "(fingerprint|biometric|udfps|fod|hbm|lhbm|dimlayer|zorder|surfaceflinger|enroll|goodix|fpc|silead|focal|egis|synaptics|onacquired|onenrollresult|onfingerdown|onfingerup|avc:\\s*denied)",
        RegexOption.IGNORE_CASE
    )

    fun buildReport(
        mode: DiagnosticMode,
        baseline: BaselineProbeResult,
        liveLogcat: String,
        elfAnalyses: List<ElfBinaryAnalysis>,
        enrollmentDurationMs: Long,
        language: AppLanguage,
        dmesgDelta: String = "",
        surfaceFlingerLiveDelta: String = "",
        sysfsTransitions: List<SysfsTransition> = emptyList(),
        procLiveMaps: List<LiveProcessMapRecord> = baseline.procLiveMaps,
        procLiveMapsText: String = baseline.procLiveMapsText
    ): FodDiagnosticReport {
        val components = mutableListOf<DiscoveredComponent>()
        val edges = mutableListOf<DependencyEdge>()
        val patches = mutableListOf<DetectedPatch>()
        val findings = mutableListOf<InvestigationFinding>()

        val propMap = parseProperties(baseline.getpropAll)

        // 1. Discover HALs from lshal, VINTF, and service list
        discoverHalComponents(baseline, components)

        // 2. Discover System Framework / Biometric / SystemUI Udfps / Display Services
        discoverSystemServices(baseline, components)

        // 3. Discover Native Libraries & ELF Binaries
        discoverElfComponents(elfAnalyses, components)

        // 4. Discover Sysfs / DRM / HBM / LHBM hardware nodes
        discoverSysfsNodes(baseline, components)

        // 5. Discover Overlays & Patches (exhaustively, never skipping any)
        discoverPatchesAndOverlays(baseline, propMap, patches, components)

        // 6. Reconstruct real SESSION FLOW from live enrollment logcat + kernel dmesg delta
        val baseSessionFlow = reconstructSessionFlow(
            liveLogcat = liveLogcat,
            dmesgDelta = dmesgDelta,
            rootGranted = baseline.environment.rootGranted,
            language = language
        ).toMutableList()

        // 7. Reconstruct stage-by-stage finger-down execution chain (T0 -> T_live -> T1)
        val fingerDownChain = reconstructFingerDownChain(
            baseline = baseline,
            sessionFlow = baseSessionFlow,
            liveLogcat = liveLogcat,
            dmesgDelta = dmesgDelta,
            surfaceFlingerLiveDelta = surfaceFlingerLiveDelta,
            sysfsTransitions = sysfsTransitions,
            enrollmentDurationMs = enrollmentDurationMs,
            language = language
        )

        // 8. Analyze completion vs explicit failure vs SILENT HAL STALL
        val blockingEvents = baseSessionFlow.filter { it.isBlockingFailure || it.status == EvidenceStatus.FAILED }
        val benignEvents = baseSessionFlow.filter { it.isBenignWarning }

        val enrollSuccess = baseSessionFlow.any {
            val ev = it.rawEvidence.lowercase()
            ev.contains("remaining=0") ||
                (ev.contains("onenrollresult") && Regex("remaining[=:\\s]+0\\b").containsMatchIn(ev)) ||
                ev.contains("enroll_complete")
        }
        val halProgressSeen = baseSessionFlow.any {
            val ev = it.rawEvidence.lowercase()
            ev.contains("onacquired") || ev.contains("onenrollresult")
        }
        val explicitFailure = blockingEvents.isNotEmpty() || baseSessionFlow.any {
            val ev = it.rawEvidence.lowercase()
            ev.contains("onerror") ||
                ev.contains("error_timeout") ||
                ev.contains("error_hw_unavailable") ||
                ev.contains("error_unable_to_process")
        }

        val fodUiOrLightActive = fingerDownChain.any {
            (it.order == 1 || it.order == 2 || it.order == 3) &&
                (it.status == EvidenceStatus.CONFIRMED || it.status == EvidenceStatus.OBSERVED)
        } || sysfsTransitions.any { it.changed } ||
            (!surfaceFlingerLiveDelta.startsWith("NO_NEW") && !surfaceFlingerLiveDelta.startsWith("SURFACEFLINGER_LIVE_UNAVAILABLE") && surfaceFlingerLiveDelta.isNotBlank()) ||
            enrollmentDurationMs >= 3000L

        val silentHalStall = !enrollSuccess && !explicitFailure && !halProgressSeen && fodUiOrLightActive

        val finalChain = if (silentHalStall) {
            fingerDownChain.map { step ->
                if (step.order == 5 && step.status != EvidenceStatus.CONFIRMED) {
                    step.copy(
                        status = EvidenceStatus.FAILED,
                        detail = if (language == AppLanguage.FR) {
                            "BLOCAGE SILENCIEUX HAL : lumière/UI FOD active mais aucun retour onAcquired / onEnrollResult / onError."
                        } else {
                            "SILENT HAL STALL: FOD light/UI active yet zero onAcquired / onEnrollResult / onError callbacks."
                        }
                    )
                } else {
                    step
                }
            }
        } else {
            fingerDownChain
        }

        if (silentHalStall) {
            baseSessionFlow += SessionEvent(
                id = "evt_silent_hal_stall",
                timestamp = "T1",
                relativeMs = enrollmentDurationMs,
                phase = "HAL_EXEC",
                component = "VendorFingerprintHAL / UdfpsSync",
                summary = if (language == AppLanguage.FR) {
                    "Blocage silencieux détecté : la zone/lumière FOD était active (${enrollmentDurationMs}ms), mais le HAL n'a émis ni progression (onAcquired/onEnrollResult) ni erreur (onError)."
                } else {
                    "Silent stall detected: FOD light/UI was active (${enrollmentDurationMs}ms), yet HAL emitted neither progress (onAcquired/onEnrollResult) nor error (onError)."
                },
                rawEvidence = "SILENT_HAL_STALL durationMs=$enrollmentDurationMs sysfsChanged=${sysfsTransitions.count { it.changed }} dmesgDelta=${dmesgDelta.lines().size}",
                status = EvidenceStatus.FAILED,
                knowledgeLevel = KnowledgeLevel.FACT,
                isBenignWarning = false,
                isBlockingFailure = true
            )
        }

        val effectiveFailed = explicitFailure || silentHalStall
        val effectiveSuccess = enrollSuccess && !effectiveFailed

        // 9. Build real Dependency Graph from discovered components
        buildDependencyGraph(components, baseSessionFlow, edges)

        // 10. Evaluate patches real effect based on live session & dumpsys
        val evaluatedPatches = evaluatePatchesRealEffect(patches, baseSessionFlow, silentHalStall, language)

        // 11. Generate Epistemic Investigation Findings
        buildFindings(
            baseline = baseline,
            components = components,
            patches = evaluatedPatches,
            elfAnalyses = elfAnalyses,
            sessionFlow = baseSessionFlow,
            fingerDownChain = finalChain,
            sysfsTransitions = sysfsTransitions,
            procLiveMaps = procLiveMaps,
            findings = findings,
            language = language
        )

        val confirmedCount = components.count { it.status == EvidenceStatus.CONFIRMED } +
            baseSessionFlow.count { it.status == EvidenceStatus.CONFIRMED }
        val observedCount = components.count { it.status == EvidenceStatus.OBSERVED } +
            baseSessionFlow.count { it.status == EvidenceStatus.OBSERVED }
        val suspectCount = components.count { it.status == EvidenceStatus.SUSPECT } +
            baseSessionFlow.count { it.status == EvidenceStatus.SUSPECT }
        val failedCount = components.count { it.status == EvidenceStatus.FAILED } +
            baseSessionFlow.count { it.status == EvidenceStatus.FAILED }
        val unknownCount = components.count { it.status == EvidenceStatus.UNKNOWN } +
            baseSessionFlow.count { it.status == EvidenceStatus.UNKNOWN }

        val updatedBlocking = baseSessionFlow.filter { it.isBlockingFailure || it.status == EvidenceStatus.FAILED }
        val firstBreak = when {
            silentHalStall -> {
                val lastOk = finalChain.lastOrNull { it.status == EvidenceStatus.CONFIRMED || it.status == EvidenceStatus.OBSERVED }
                val firstBroken = finalChain.firstOrNull { it.status == EvidenceStatus.FAILED || it.status == EvidenceStatus.SUSPECT }
                    ?: finalChain.lastOrNull()
                if (language == AppLanguage.FR) {
                    "Dernière étape confirmée : [${lastOk?.stage ?: "UI/FOD"}] → Rupture silencieuse à [${firstBroken?.stage ?: "HAL"}] : ${firstBroken?.detail.orEmpty()}"
                } else {
                    "Last confirmed stage: [${lastOk?.stage ?: "UI/FOD"}] → Silent break at [${firstBroken?.stage ?: "HAL"}]: ${firstBroken?.detail.orEmpty()}"
                }
            }
            updatedBlocking.isNotEmpty() -> {
                val blk = updatedBlocking.first()
                "[${blk.phase}] ${blk.component}: ${blk.summary} (${blk.rawEvidence.take(160)})"
            }
            components.any { it.status == EvidenceStatus.FAILED } -> {
                val c = components.first { it.status == EvidenceStatus.FAILED }
                "[${c.category}] ${c.name}: ${c.accessNote ?: c.path}"
            }
            else -> if (language == AppLanguage.FR) {
                "Aucune rupture bloquante démontrée dans les traces accessibles."
            } else {
                "No blocking break demonstrated within accessible traces."
            }
        }

        val noiseNote = when {
            effectiveSuccess && benignEvents.isNotEmpty() -> {
                if (language == AppLanguage.FR) {
                    "Enregistrement réussi malgré ${benignEvents.size} avertissement(s) non bloquant(s) observé(s) dans les logs."
                } else {
                    "Enrollment succeeded despite ${benignEvents.size} non-blocking warning(s) observed in logs."
                }
            }
            silentHalStall -> {
                if (language == AppLanguage.FR) {
                    "Échec silencieux caractérisé : la lumière FOD réagit, mais la chaîne HBM/Touch/HAL ne transmet aucun événement d'acquisition au framework."
                } else {
                    "Characterized silent stall: FOD light activates, but the HBM/Touch/HAL chain delivers zero acquisition callbacks to the framework."
                }
            }
            effectiveFailed && benignEvents.isNotEmpty() -> {
                if (language == AppLanguage.FR) {
                    "${benignEvents.size} avertissement(s) bénin(s) et ${updatedBlocking.size} rupture(s) bloquante(s) observés."
                } else {
                    "${benignEvents.size} benign warning(s) and ${updatedBlocking.size} blocking break(s) observed."
                }
            }
            else -> {
                if (language == AppLanguage.FR) {
                    "Distinction effectuée entre bruit système toléré et ruptures réelles."
                } else {
                    "Separated tolerated system log noise from real breaks."
                }
            }
        }

        val overallOutcome = when {
            silentHalStall -> if (language == AppLanguage.FR) {
                "BLOCAGE SILENCIEUX DÉTECTÉ (AUCUN RETOUR HAL)"
            } else {
                "SILENT HAL STALL DETECTED (NO HAL RESPONSE)"
            }
            baseSessionFlow.isEmpty() -> if (language == AppLanguage.FR) {
                "INCOMPLET / TRACE LIVE RESTREINTE"
            } else {
                "INCOMPLETE / RESTRICTED LIVE TRACE"
            }
            effectiveSuccess -> if (language == AppLanguage.FR) {
                "SUCCÈS D'ENREGISTREMENT OBSERVÉ"
            } else {
                "ENROLLMENT SUCCESS OBSERVED"
            }
            effectiveFailed -> if (language == AppLanguage.FR) {
                "BLOCAGE RÉEL DÉTECTÉ"
            } else {
                "REAL ENROLLMENT BLOCK DETECTED"
            }
            halProgressSeen -> if (language == AppLanguage.FR) {
                "ACQUISITION PARTIELLE OBSERVÉE (NON TERMINÉE)"
            } else {
                "PARTIAL ACQUISITION OBSERVED (INCOMPLETE)"
            }
            else -> if (language == AppLanguage.FR) {
                "SESSION OBSERVÉE (ÉTAT INTERMÉDIAIRE)"
            } else {
                "SESSION OBSERVED (INTERMEDIATE STATE)"
            }
        }

        val fullElfText = buildString {
            elfAnalyses.forEach { elf ->
                appendLine("====================================================")
                appendLine("BINARY: ${elf.path} (${elf.architecture}, ${elf.fileSizeBytes} bytes)")
                appendLine("Readable: ${elf.isReadable} | AccessError: ${elf.accessError ?: "none"}")
                appendLine("DT_NEEDED: ${elf.dtNeeded.joinToString(", ")}")
                appendLine("FOD Symbols (${elf.fodSymbols.size}):")
                elf.fodSymbols.forEach { appendLine("  - $it") }
                appendLine("FOD Strings (${elf.fodStrings.size}):")
                elf.fodStrings.forEach { appendLine("  - $it") }
                if (elf.disassemblyPseudoCode.isNotBlank()) {
                    appendLine("AArch64 Disassembly / Pseudo-code:")
                    appendLine(elf.disassemblyPseudoCode)
                }
                appendLine()
            }
        }

        val nowIso = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).format(Date())

        return FodDiagnosticReport(
            sessionId = UUID.randomUUID().toString().take(8),
            mode = mode,
            createdAtIso = nowIso,
            enrollmentDurationMs = enrollmentDurationMs,
            environment = baseline.environment,
            sessionFlow = baseSessionFlow,
            components = components.distinctBy { it.id },
            dependencyEdges = edges,
            patches = evaluatedPatches,
            elfAnalyses = elfAnalyses,
            findings = findings,
            summary = DiagnosticSummary(
                overallOutcome = overallOutcome,
                enrollmentObserved = baseSessionFlow.isNotEmpty() || sysfsTransitions.any { it.changed } || enrollmentDurationMs >= 3000L,
                enrollmentSucceeded = when {
                    effectiveSuccess -> true
                    effectiveFailed -> false
                    else -> null
                },
                realSuccessDespiteNoiseNote = noiseNote,
                firstDemonstratedBreak = firstBreak,
                confirmedCount = confirmedCount,
                observedCount = observedCount,
                suspectCount = suspectCount,
                failedCount = failedCount,
                unknownCount = unknownCount
            ),
            rawArtifacts = RawArtifactsBundle(
                logcatBaseline = baseline.logcatBaseline,
                logcatEnrollment = liveLogcat,
                dumpsysFingerprint = baseline.dumpsysFingerprint,
                dumpsysBiometric = baseline.dumpsysBiometric,
                dumpsysSurfaceFlinger = baseline.dumpsysSurfaceFlinger,
                dumpsysDisplay = baseline.dumpsysDisplay,
                dumpsysOverlay = baseline.dumpsysOverlay,
                lshalOutput = baseline.lshalOutput,
                vintfManifests = baseline.vintfManifests,
                serviceList = baseline.serviceList,
                getpropAll = baseline.getpropAll,
                sysfsFodNodes = baseline.sysfsFodNodes,
                selinuxDenials = baseline.selinuxDenials,
                initRcSnippets = baseline.initRcSnippets,
                elfDisassemblyFull = fullElfText,
                dmesgDelta = dmesgDelta,
                surfaceFlingerLiveDelta = surfaceFlingerLiveDelta,
                overlayDeepInspect = baseline.overlayDeepInspect,
                fileProvenanceIndex = baseline.fileProvenanceIndex,
                procLiveMaps = procLiveMapsText,
                dexSourceExtract = baseline.dexSourceExtractText
            ),
            fingerDownChain = finalChain,
            sysfsTransitions = sysfsTransitions,
            overlayInspections = baseline.overlayInspections,
            fileProvenance = baseline.fileProvenance,
            procLiveMaps = procLiveMaps,
            dexSourceExtracts = baseline.dexSourceExtracts
        )
    }

    private fun reconstructFingerDownChain(
        baseline: BaselineProbeResult,
        sessionFlow: List<SessionEvent>,
        liveLogcat: String,
        dmesgDelta: String,
        surfaceFlingerLiveDelta: String,
        sysfsTransitions: List<SysfsTransition>,
        enrollmentDurationMs: Long,
        language: AppLanguage
    ): List<FingerDownStep> {
        val logLower = liveLogcat.lowercase()
        val dmesgLower = dmesgDelta.lowercase()
        val sfLower = surfaceFlingerLiveDelta.lowercase()

        // 1. Biometric / Enrollment client active
        val enrollEvt = sessionFlow.firstOrNull {
            it.phase == "ENROLLMENT" ||
                it.rawEvidence.contains("startPreparedClient", true) ||
                it.rawEvidence.contains("enroll(", true)
        }
        val step1 = FingerDownStep(
            order = 1,
            stage = if (language == AppLanguage.FR) "1. Client Enrôlement (Framework)" else "1. Enrollment Client (Framework)",
            status = when {
                enrollEvt != null -> EvidenceStatus.CONFIRMED
                enrollmentDurationMs >= 2500L -> EvidenceStatus.OBSERVED
                else -> EvidenceStatus.UNKNOWN
            },
            detail = when {
                enrollEvt != null -> enrollEvt.summary
                enrollmentDurationMs >= 2500L -> if (language == AppLanguage.FR) {
                    "Session d'enrôlement active (${enrollmentDurationMs}ms) sans trace explicite startPreparedClient dans le tampon."
                } else {
                    "Enrollment session active (${enrollmentDurationMs}ms) without explicit startPreparedClient line in buffer."
                }
                else -> if (language == AppLanguage.FR) "Aucune activité d'enrôlement observée." else "No enrollment activity observed."
            },
            evidence = enrollEvt?.rawEvidence.orEmpty()
        )

        // 2. FOD Overlay / SurfaceFlinger illumination layer
        val fodUiEvt = sessionFlow.firstOrNull {
            it.phase == "FOD_OVERLAY" ||
                it.rawEvidence.contains("udfps", true) ||
                it.rawEvidence.contains("dimlayer", true) ||
                it.rawEvidence.contains("BiometricPrompt", true)
        }
        val hasSfLayer = sfLower.contains("udfps") || sfLower.contains("fod") || sfLower.contains("dim") || sfLower.contains("fingerprint")
        val step2 = FingerDownStep(
            order = 2,
            stage = if (language == AppLanguage.FR) "2. UI / Lumière FOD (SystemUI & SurfaceFlinger)" else "2. FOD UI / Illumination (SystemUI & SurfaceFlinger)",
            status = when {
                fodUiEvt?.isBlockingFailure == true -> EvidenceStatus.FAILED
                fodUiEvt != null || hasSfLayer -> EvidenceStatus.CONFIRMED
                enrollmentDurationMs >= 3000L -> EvidenceStatus.OBSERVED
                else -> EvidenceStatus.UNKNOWN
            },
            detail = when {
                fodUiEvt != null -> fodUiEvt.summary
                hasSfLayer -> "SurfaceFlinger delta: ${surfaceFlingerLiveDelta.lines().take(3).joinToString(" | ")}"
                enrollmentDurationMs >= 3000L -> if (language == AppLanguage.FR) {
                    "Zone lumineuse FOD activée visuellement pendant la session (couche non capturée dans les tampons)."
                } else {
                    "FOD illumination zone active during session (layer not captured in buffers)."
                }
                else -> if (language == AppLanguage.FR) "Couche FOD non observée." else "FOD layer not observed."
            },
            evidence = (fodUiEvt?.rawEvidence ?: surfaceFlingerLiveDelta).take(220)
        )

        // 3. HBM / Sysfs node transition
        val changedSysfs = sysfsTransitions.filter { it.changed }
        val hbmEvt = sessionFlow.firstOrNull {
            it.phase == "DISPLAY_HBM" || logLower.contains("hbm") || logLower.contains("lhbm") || logLower.contains("disp_param")
        }
        val sysfsDenied = dmesgLower.contains("avc: denied") && (dmesgLower.contains("sysfs") || dmesgLower.contains("drm") || dmesgLower.contains("fod"))
        val step3 = FingerDownStep(
            order = 3,
            stage = if (language == AppLanguage.FR) "3. HBM / Nœuds sysfs DRM & Touch" else "3. Display HBM / DRM & Touch Sysfs",
            status = when {
                sysfsDenied || hbmEvt?.isBlockingFailure == true -> EvidenceStatus.FAILED
                changedSysfs.isNotEmpty() || hbmEvt?.status == EvidenceStatus.CONFIRMED -> EvidenceStatus.CONFIRMED
                sysfsTransitions.isNotEmpty() -> EvidenceStatus.SUSPECT
                else -> EvidenceStatus.UNKNOWN
            },
            detail = when {
                sysfsDenied -> if (language == AppLanguage.FR) "Accès HBM/sysfs bloqué par SELinux." else "HBM/sysfs access blocked by SELinux."
                changedSysfs.isNotEmpty() -> changedSysfs.take(4).joinToString(" | ") { "${it.nodePath.substringAfterLast('/')}: ${it.beforeValue} -> ${it.afterValue}" }
                hbmEvt != null -> hbmEvt.summary
                sysfsTransitions.isNotEmpty() -> if (language == AppLanguage.FR) {
                    "${sysfsTransitions.size} nœuds sysfs surveillés mais AUCUNE transition observée pendant l'appui doigt !"
                } else {
                    "${sysfsTransitions.size} sysfs nodes polled yet ZERO state transitions observed during finger touch!"
                }
                else -> if (language == AppLanguage.FR) "Nœuds sysfs non lisibles (${if (baseline.environment.rootGranted) "aucun découvert" else "root désactivé"})." else "Sysfs nodes unreadable."
            },
            evidence = changedSysfs.joinToString("\n") { "${it.nodePath}: ${it.beforeValue} -> ${it.liveValues} -> ${it.afterValue}" }.take(240)
        )

        // 4. Kernel driver / dmesg events
        val kernelLines = if (!dmesgDelta.startsWith("DMESG_UNAVAILABLE") && !dmesgDelta.startsWith("NO_NEW_FOD")) {
            dmesgDelta.lines().filter { it.isNotBlank() }
        } else {
            emptyList()
        }
        val kernelError = kernelLines.any { it.contains("fail", true) || it.contains("err", true) || it.contains("avc: denied", true) }
        val step4 = FingerDownStep(
            order = 4,
            stage = if (language == AppLanguage.FR) "4. Noyau / Pilote Touch-FOD (dmesg)" else "4. Kernel / Touch-FOD Driver (dmesg)",
            status = when {
                !baseline.environment.rootGranted -> EvidenceStatus.UNKNOWN
                kernelError -> EvidenceStatus.FAILED
                kernelLines.isNotEmpty() -> EvidenceStatus.CONFIRMED
                else -> EvidenceStatus.SUSPECT
            },
            detail = when {
                !baseline.environment.rootGranted -> if (language == AppLanguage.FR) "dmesg inaccessible sans Root." else "dmesg unavailable without Root."
                kernelLines.isNotEmpty() -> "${kernelLines.size} événement(s) kernel capturés pendant l'appui."
                else -> if (language == AppLanguage.FR) {
                    "Aucun événement kernel FOD/goodix/touch_dev/hbm émis dans dmesg pendant l'appui du doigt."
                } else {
                    "Zero FOD/goodix/touch_dev/hbm kernel events emitted in dmesg during finger touch."
                }
            },
            evidence = kernelLines.take(5).joinToString("\n").take(260)
        )

        // 5. Vendor Fingerprint HAL callbacks
        val onFingerDownSeen = logLower.contains("onfingerdown") || logLower.contains("fod_press") || logLower.contains("extcmd")
        val onAcquiredSeen = logLower.contains("onacquired")
        val onEnrollResultSeen = logLower.contains("onenrollresult")
        val onErrorEvent = sessionFlow.firstOrNull { it.isBlockingFailure || it.rawEvidence.contains("onError", true) }
        val step5 = FingerDownStep(
            order = 5,
            stage = if (language == AppLanguage.FR) "5. HAL Biométrique Vendor & Callbacks" else "5. Vendor Biometric HAL & Callbacks",
            status = when {
                onEnrollResultSeen || onAcquiredSeen -> EvidenceStatus.CONFIRMED
                onErrorEvent != null -> EvidenceStatus.FAILED
                onFingerDownSeen -> EvidenceStatus.SUSPECT
                else -> EvidenceStatus.UNKNOWN
            },
            detail = when {
                onEnrollResultSeen -> if (language == AppLanguage.FR) "onEnrollResult observé : capture complétée par le HAL." else "onEnrollResult observed: capture completed by HAL."
                onAcquiredSeen -> if (language == AppLanguage.FR) "onAcquired observé : le HAL capte le doigt." else "onAcquired observed: HAL receives finger signal."
                onErrorEvent != null -> onErrorEvent.summary
                onFingerDownSeen -> if (language == AppLanguage.FR) {
                    "onFingerDown envoyé au HAL mais aucun onAcquired/onEnrollResult reçu en retour."
                } else {
                    "onFingerDown sent to HAL yet zero onAcquired/onEnrollResult returned."
                }
                else -> if (language == AppLanguage.FR) {
                    "Aucun signal onFingerDown / onAcquired / onEnrollResult observé côté HAL."
                } else {
                    "No onFingerDown / onAcquired / onEnrollResult signal observed from HAL."
                }
            },
            evidence = sessionFlow.filter {
                val r = it.rawEvidence.lowercase()
                r.contains("onfingerdown") || r.contains("onacquired") || r.contains("onenrollresult") || r.contains("onerror")
            }.take(4).joinToString("\n") { it.rawEvidence }.take(260)
        )

        return listOf(step1, step2, step3, step4, step5)
    }

    private fun discoverHalComponents(
        baseline: BaselineProbeResult,
        out: MutableList<DiscoveredComponent>
    ) {
        val combined = listOf(baseline.lshalOutput, baseline.vintfManifests, baseline.serviceList)
            .joinToString("\n")
        val halPatterns = Regex(
            "(android\\.hardware\\.biometrics\\.fingerprint[@\\d.]*[:/\\w.-]*|vendor\\.[\\w.]+fingerprint[\\w.@:/-]*|vendor\\.[\\w.]+biometrics[\\w.@:/-]*|vendor\\.[\\w.]+display[\\w.@:/-]*)",
            RegexOption.IGNORE_CASE
        )

        val matched = halPatterns.findAll(combined).map { it.value.trim() }.distinct().toList()
        if (matched.isEmpty()) {
            out += DiscoveredComponent(
                id = "hal_fingerprint_unknown",
                name = "Fingerprint HAL (HIDL/AIDL)",
                category = ComponentCategory.HAL,
                version = "UNKNOWN",
                interfaceType = "UNKNOWN",
                path = "/vendor/bin/hw/*",
                status = if (baseline.environment.rootGranted) EvidenceStatus.FAILED else EvidenceStatus.UNKNOWN,
                knowledgeLevel = KnowledgeLevel.FACT,
                accessNote = if (baseline.environment.rootGranted) {
                    "No fingerprint HAL instance detected in lshal/VINTF/service list."
                } else {
                    "lshal/VINTF restricted without root; HAL identity cannot be confirmed."
                }
            )
        } else {
            matched.forEachIndexed { idx, halName ->
                val isAidl = halName.contains("IFingerprint", true) || !halName.contains("@")
                val version = Regex("@(\\d+\\.\\d+)").find(halName)?.groupValues?.get(1)
                    ?: if (isAidl) "AIDL" else "UNKNOWN"
                val status = if (baseline.lshalOutput.contains(halName) || baseline.serviceList.contains(halName)) {
                    EvidenceStatus.CONFIRMED
                } else {
                    EvidenceStatus.OBSERVED
                }
                out += DiscoveredComponent(
                    id = "hal_${idx}_${halName.hashCode()}",
                    name = halName,
                    category = ComponentCategory.HAL,
                    version = version,
                    interfaceType = if (isAidl) "AIDL Binder" else "HIDL hwbinder",
                    path = "VINTF / Binder",
                    status = status,
                    knowledgeLevel = KnowledgeLevel.FACT,
                    metadata = mapOf("source" to if (baseline.lshalOutput.contains(halName)) "lshal" else "vintf/service_list")
                )
            }
        }
    }

    private fun discoverSystemServices(
        baseline: BaselineProbeResult,
        out: MutableList<DiscoveredComponent>
    ) {
        val fpPresent = baseline.dumpsysFingerprint.isNotBlank() &&
            !baseline.dumpsysFingerprint.contains("Can't find service", true)
        val udfpsInfo = Regex("(udfps|fod|sensorLocation|sensorProps|HBM|LHBM).*", RegexOption.IGNORE_CASE)
            .findAll(baseline.dumpsysFingerprint + "\n" + baseline.dumpsysBiometric)
            .map { it.value.trim().take(120) }
            .distinct()
            .take(8)
            .joinToString(" | ")

        out += DiscoveredComponent(
            id = "svc_fingerprint",
            name = "FingerprintService / BiometricService",
            category = ComponentCategory.SERVICE,
            version = "Android ${baseline.environment.androidRelease} (API ${baseline.environment.sdkInt})",
            interfaceType = "SystemServer Binder",
            path = "system_server",
            status = when {
                fpPresent && udfpsInfo.isNotBlank() -> EvidenceStatus.CONFIRMED
                fpPresent -> EvidenceStatus.OBSERVED
                baseline.environment.biometricHardwareStatus.contains("BIOMETRIC_ERROR_NO_HARDWARE") -> EvidenceStatus.FAILED
                else -> EvidenceStatus.UNKNOWN
            },
            knowledgeLevel = KnowledgeLevel.FACT,
            metadata = mapOf(
                "biometricManager" to baseline.environment.biometricHardwareStatus,
                "udfpsHints" to udfpsInfo.ifBlank { "none observed in accessible dumpsys" }
            ),
            accessNote = if (!fpPresent) "dumpsys fingerprint inaccessible or empty (Permission denied without shell/root)." else null
        )

        val sfPresent = baseline.dumpsysSurfaceFlinger.isNotBlank()
        val sfFodLayer = Regex("(Udfps|Fod|Fingerprint|HBM|Dim|ColorMode).*", RegexOption.IGNORE_CASE)
            .findAll(baseline.dumpsysSurfaceFlinger)
            .map { it.value.trim().take(120) }
            .distinct()
            .take(6)
            .joinToString(" | ")

        out += DiscoveredComponent(
            id = "svc_surfaceflinger",
            name = "SurfaceFlinger / HWC Display Pipeline",
            category = ComponentCategory.DISPLAY_PIPELINE,
            version = "Display API ${baseline.environment.sdkInt}",
            interfaceType = "Composer HAL / DRM",
            path = "/system/bin/surfaceflinger",
            status = if (sfPresent) EvidenceStatus.CONFIRMED else EvidenceStatus.UNKNOWN,
            knowledgeLevel = KnowledgeLevel.FACT,
            metadata = mapOf(
                "displayModes" to baseline.environment.displayModesSummary,
                "fodLayers" to sfFodLayer.ifBlank { "none observed at baseline" }
            ),
            accessNote = if (!sfPresent) "dumpsys SurfaceFlinger blocked without root/DUMP permission." else null
        )
    }

    private fun discoverElfComponents(
        elfAnalyses: List<ElfBinaryAnalysis>,
        out: MutableList<DiscoveredComponent>
    ) {
        if (elfAnalyses.isEmpty()) {
            out += DiscoveredComponent(
                id = "elf_none",
                name = "Vendor/System FOD ELF Binaries",
                category = ComponentCategory.LIBRARY,
                version = "UNKNOWN",
                interfaceType = "ELF",
                path = "/vendor/bin/hw/ & /vendor/lib64/",
                status = EvidenceStatus.UNKNOWN,
                knowledgeLevel = KnowledgeLevel.FACT,
                accessNote = "No accessible FOD/fingerprint ELF binaries discovered (SELinux/non-root restriction or non-standard path)."
            )
            return
        }

        elfAnalyses.forEachIndexed { idx, elf ->
            out += DiscoveredComponent(
                id = "elf_${idx}_${elf.path.hashCode()}",
                name = elf.path.substringAfterLast('/'),
                category = if (elf.path.contains("/bin/")) ComponentCategory.HAL else ComponentCategory.LIBRARY,
                version = elf.architecture,
                interfaceType = "ELF (${elf.fileSizeBytes} bytes)",
                path = elf.path,
                status = if (elf.isReadable) EvidenceStatus.CONFIRMED else EvidenceStatus.UNKNOWN,
                knowledgeLevel = KnowledgeLevel.FACT,
                dependencies = elf.dtNeeded,
                metadata = mapOf(
                    "symbolsCount" to elf.fodSymbols.size.toString(),
                    "stringsCount" to elf.fodStrings.size.toString()
                ),
                accessNote = elf.accessError
            )
        }
    }

    private fun discoverSysfsNodes(
        baseline: BaselineProbeResult,
        out: MutableList<DiscoveredComponent>
    ) {
        val sections = baseline.sysfsFodNodes.split("=== ")
            .map { it.trim() }
            .filter { it.isNotBlank() }

        if (sections.isEmpty()) {
            out += DiscoveredComponent(
                id = "sysfs_fod_unknown",
                name = "Sysfs HBM / LHBM / FOD Nodes",
                category = ComponentCategory.SYSFS_NODE,
                version = "Kernel Sysfs",
                interfaceType = "sysfs/ioctl",
                path = "/sys/class/drm/ & /sys/devices/",
                status = EvidenceStatus.UNKNOWN,
                knowledgeLevel = KnowledgeLevel.FACT,
                accessNote = "No readable FOD/HBM sysfs nodes found (SELinux/non-root restriction or vendor uses DRM ioctl/AIDL)."
            )
            return
        }

        sections.forEachIndexed { idx, block ->
            val lines = block.lines()
            val nodePath = lines.firstOrNull()?.removeSuffix("===")?.trim() ?: return@forEachIndexed
            val value = lines.drop(1).joinToString(" ").trim()
            val denied = value.contains("Permission denied", true)
            out += DiscoveredComponent(
                id = "sysfs_${idx}_${nodePath.hashCode()}",
                name = nodePath.substringAfterLast('/'),
                category = ComponentCategory.SYSFS_NODE,
                version = "Kernel",
                interfaceType = "sysfs",
                path = nodePath,
                status = if (denied) EvidenceStatus.UNKNOWN else EvidenceStatus.CONFIRMED,
                knowledgeLevel = KnowledgeLevel.FACT,
                metadata = mapOf("value" to value.take(180)),
                accessNote = if (denied) "Permission denied reading $nodePath" else null
            )
        }
    }

    private fun discoverPatchesAndOverlays(
        baseline: BaselineProbeResult,
        propMap: Map<String, String>,
        patches: MutableList<DetectedPatch>,
        components: MutableList<DiscoveredComponent>
    ) {
        val overlayByPkg = baseline.overlayInspections.associateBy { it.packageName }
        val propFiles = baseline.fileProvenance.filter { it.category == "PROP_FILE" }

        propMap.entries
            .filter { patchPropRegex.matches(it.key) || it.key.contains("fod", true) || it.key.contains("udfps", true) || it.key.contains("phh", true) }
            .forEachIndexed { idx, (k, v) ->
                val isPhhOrGsi = k.contains("phh", true) || k.contains("treble", true) || k.contains("sys.fod", true)
                val originProp = propFiles.firstOrNull { pf ->
                    pf.importantContents.any { line -> line.startsWith("$k=") || line.contains("[$k]") || line.contains(k) }
                }
                val resolvedSource = originProp?.filePath ?: "SystemProperties (runtime/default)"
                val resolvedDir = originProp?.directory ?: "runtime"
                patches += DetectedPatch(
                    id = "patch_prop_$idx",
                    name = k,
                    source = "SystemProperties ($resolvedSource)",
                    scope = if (isPhhOrGsi) "GSI / Treble Patch Prop" else "Device / Vendor Prop",
                    target = resolvedSource,
                    rawValue = v,
                    status = EvidenceStatus.CONFIRMED,
                    realObservedEffect = "Pending live trace correlation",
                    note = "Prop [$k]=[$v] | File=$resolvedSource | Dir=$resolvedDir"
                )
                components += DiscoveredComponent(
                    id = "prop_$idx",
                    name = k,
                    category = if (isPhhOrGsi) ComponentCategory.PATCH else ComponentCategory.PROPERTY,
                    version = v.ifBlank { "<empty>" },
                    interfaceType = "SystemProperty",
                    path = if (originProp != null) "${originProp.filePath} ($k)" else k,
                    status = EvidenceStatus.CONFIRMED,
                    knowledgeLevel = KnowledgeLevel.FACT,
                    metadata = buildMap {
                        if (originProp != null) {
                            put("file", originProp.filePath)
                            put("directory", originProp.directory)
                        }
                        put("value", v.take(120))
                    }
                )
            }

        val seenOverlayPkgs = linkedSetOf<String>()
        val overlayEntries = baseline.dumpsysOverlay.lineSequence()
            .map { it.trim() }
            .filter { line ->
                val l = line.lowercase()
                l.startsWith("[x]") || l.startsWith("[ ]") || l.contains("state_enabled") ||
                    l.contains("fod") || l.contains("udfps") || l.contains("treble") ||
                    l.contains("fingerprint") || l.contains("biometric") || l.contains("systemui") ||
                    l.contains("overlay")
            }
            .mapNotNull { trimmed ->
                val enabled = trimmed.startsWith("[x]", true) || trimmed.contains("STATE_ENABLED")
                val pkg = trimmed.removePrefix("[x]").removePrefix("[ ]").trim().substringBefore(":").substringBefore(" ")
                if (pkg.isBlank()) null else Triple(pkg, enabled, trimmed)
            }
            .distinctBy { it.first }
            .sortedWith(
                compareByDescending<Triple<String, Boolean, String>> { overlayByPkg[it.first]?.fodRelevanceScore ?: -1 }
                    .thenByDescending { overlayByPkg[it.first]?.provenInLiveMaps == true }
                    .thenByDescending { it.second }
                    .thenBy { it.first }
            )
            .take(80)

        overlayEntries.forEachIndexed { idx, (pkg, enabled, trimmed) ->
            seenOverlayPkgs += pkg
            val deep = overlayByPkg[pkg]
            val resolvedApk = deep?.apkPath?.takeIf { it != "UNKNOWN" } ?: pkg
            val resolvedDir = deep?.directory?.takeIf { it != "UNKNOWN" } ?: "UNKNOWN"
            val keyEntriesPreview = (deep?.decodedArscEntries.orEmpty() + deep?.fodConfigEntries.orEmpty())
                .distinct().take(6).joinToString(" ; ")
            patches += DetectedPatch(
                id = "patch_rro_$idx",
                name = pkg,
                source = if (deep != null && deep.apkPath != "UNKNOWN") "OverlayManager (${deep.apkPath})" else "OverlayManager (cmd overlay list)",
                scope = if ((deep?.fodRelevanceScore ?: 0) >= 40) "Proven FOD RRO Overlay" else "RRO Overlay",
                target = deep?.targetPackage?.takeIf { it.isNotBlank() } ?: pkg,
                rawValue = if (enabled) "ENABLED" else "DISABLED/STATE_OTHER",
                status = when {
                    enabled && (deep?.fodRelevanceScore ?: 0) >= 40 -> EvidenceStatus.CONFIRMED
                    enabled -> EvidenceStatus.OBSERVED
                    else -> EvidenceStatus.OBSERVED
                },
                realObservedEffect = when {
                    (deep?.lookupWinners?.isNotEmpty() == true) -> "Active lookup winner (${deep.lookupWinners.size} key(s))"
                    (deep?.fodRelevanceScore ?: 0) >= 40 -> "Contains decoded FOD ARSC/XML overrides (score=${deep?.fodRelevanceScore})"
                    enabled -> "Active RRO overlay"
                    else -> "Present but inactive"
                },
                note = buildString {
                    append(trimmed)
                    if (deep != null) {
                        append(" | score=${deep.fodRelevanceScore} | liveMapped=${deep.provenInLiveMaps} | APK=${deep.apkPath} | Dir=$resolvedDir | target=${deep.targetPackage} | prio=${deep.priority}")
                        if (deep.lookupWinners.isNotEmpty()) append(" | Lookup: ${deep.lookupWinners.take(3).joinToString("; ")}")
                        if (keyEntriesPreview.isNotBlank()) append(" | Keys: $keyEntriesPreview")
                    }
                }
            )
            components += DiscoveredComponent(
                id = "overlay_${idx}_${pkg.hashCode()}",
                name = pkg,
                category = ComponentCategory.OVERLAY,
                version = if (enabled) "ENABLED" else "INACTIVE",
                interfaceType = if (deep?.targetPackage?.isNotBlank() == true) "RRO -> ${deep.targetPackage}" else "RRO",
                path = resolvedApk,
                status = if (enabled) EvidenceStatus.CONFIRMED else EvidenceStatus.OBSERVED,
                knowledgeLevel = KnowledgeLevel.FACT,
                metadata = buildMap {
                    put("apkPath", deep?.apkPath ?: "UNKNOWN")
                    put("directory", resolvedDir)
                    if (deep != null) {
                        put("fodRelevanceScore", deep.fodRelevanceScore.toString())
                        put("provenInLiveMaps", deep.provenInLiveMaps.toString())
                        if (deep.lookupWinners.isNotEmpty()) put("lookupWinners", deep.lookupWinners.joinToString(" | ").take(240))
                        if (deep.decodedArscEntries.isNotEmpty()) put("decodedArscEntries", deep.decodedArscEntries.take(8).joinToString(" | ").take(280))
                        if (deep.targetPackage.isNotBlank()) put("targetPackage", deep.targetPackage)
                        put("priority", deep.priority.toString())
                    }
                    if (keyEntriesPreview.isNotBlank()) put("internalKeys", keyEntriesPreview.take(240))
                }
            )
        }

        // Also include deep-inspected overlays discovered via dumpsys overlay / partitions that weren't in cmd overlay list lines
        baseline.overlayInspections.filter { it.packageName !in seenOverlayPkgs }.forEachIndexed { idx, deep ->
            seenOverlayPkgs += deep.packageName
            val keyEntriesPreview = (deep.decodedArscEntries + deep.fodConfigEntries).distinct().take(6).joinToString(" ; ")
            patches += DetectedPatch(
                id = "patch_rro_deep_$idx",
                name = deep.packageName,
                source = "OverlayManager (${deep.apkPath})",
                scope = if (deep.fodRelevanceScore >= 40) "Proven FOD RRO Overlay" else "RRO Overlay",
                target = deep.targetPackage.ifBlank { deep.packageName },
                rawValue = if (deep.isEnabled) "ENABLED" else "DISABLED/STATE_OTHER",
                status = if (deep.isEnabled) EvidenceStatus.CONFIRMED else EvidenceStatus.OBSERVED,
                realObservedEffect = if (deep.fodRelevanceScore >= 40) "Decoded FOD ARSC/XML (score=${deep.fodRelevanceScore})" else if (deep.isEnabled) "Active RRO overlay" else "Present but inactive",
                note = "score=${deep.fodRelevanceScore} | liveMapped=${deep.provenInLiveMaps} | APK=${deep.apkPath} | Dir=${deep.directory} | target=${deep.targetPackage} | Keys: $keyEntriesPreview"
            )
            components += DiscoveredComponent(
                id = "overlay_deep_${idx}_${deep.packageName.hashCode()}",
                name = deep.packageName,
                category = ComponentCategory.OVERLAY,
                version = if (deep.isEnabled) "ENABLED" else "INACTIVE",
                interfaceType = if (deep.targetPackage.isNotBlank()) "RRO -> ${deep.targetPackage}" else "RRO",
                path = deep.apkPath.takeIf { it != "UNKNOWN" } ?: deep.packageName,
                status = if (deep.isEnabled) EvidenceStatus.CONFIRMED else EvidenceStatus.OBSERVED,
                knowledgeLevel = KnowledgeLevel.FACT,
                metadata = buildMap {
                    put("apkPath", deep.apkPath)
                    put("directory", deep.directory)
                    put("fodRelevanceScore", deep.fodRelevanceScore.toString())
                    put("provenInLiveMaps", deep.provenInLiveMaps.toString())
                    if (deep.lookupWinners.isNotEmpty()) put("lookupWinners", deep.lookupWinners.joinToString(" | ").take(240))
                    if (deep.decodedArscEntries.isNotEmpty()) put("decodedArscEntries", deep.decodedArscEntries.take(8).joinToString(" | ").take(280))
                    if (deep.targetPackage.isNotBlank()) put("targetPackage", deep.targetPackage)
                    put("priority", deep.priority.toString())
                    if (keyEntriesPreview.isNotBlank()) put("internalKeys", keyEntriesPreview.take(240))
                }
            )
        }

        baseline.installedOverlayPackages.forEachIndexed { idx, pkg ->
            if (patches.none { it.name.contains(pkg) }) {
                val deep = overlayByPkg[pkg]
                patches += DetectedPatch(
                    id = "patch_pkg_$idx",
                    name = pkg,
                    source = "PackageManager (${deep?.apkPath ?: "installed"})",
                    scope = "Installed Overlay/FOD Package",
                    target = deep?.targetPackage?.ifBlank { pkg } ?: pkg,
                    rawValue = "INSTALLED",
                    status = EvidenceStatus.OBSERVED,
                    realObservedEffect = "Installed package (activation state from OverlayManager if accessible)",
                    note = "$pkg | APK=${deep?.apkPath ?: "UNKNOWN"} | Dir=${deep?.directory ?: "UNKNOWN"}"
                )
            }
        }

        baseline.initRcSnippets.lineSequence()
            .filter { it.isNotBlank() }
            .take(40)
            .forEachIndexed { idx, line ->
                val rcFile = line.substringBefore(":")
                patches += DetectedPatch(
                    id = "patch_init_$idx",
                    name = rcFile,
                    source = "init.rc ($rcFile)",
                    scope = "Init Boot/Trigger Script",
                    target = rcFile,
                    rawValue = line.substringAfter(":").trim(),
                    status = EvidenceStatus.OBSERVED,
                    realObservedEffect = "Init trigger definition",
                    note = "Dir=${rcFile.substringBeforeLast('/', "UNKNOWN")} | ${line.take(180)}"
                )
            }

        // Add non-overlay FileProvenanceArtifacts as rich DiscoveredComponents so UI & Comparator inspect exact files/directories
        baseline.fileProvenance
            .filter { it.category != "OVERLAY_APK" }
            .take(60)
            .forEachIndexed { idx, prov ->
                val cat = when (prov.category) {
                    "SELINUX_POLICY" -> ComponentCategory.SELINUX
                    "PROP_FILE" -> ComponentCategory.PROPERTY
                    "DISPLAY_CONFIG" -> ComponentCategory.DISPLAY_PIPELINE
                    "SYSTEMUI_FRAMEWORK" -> ComponentCategory.SERVICE
                    else -> ComponentCategory.PATCH
                }
                components += DiscoveredComponent(
                    id = "prov_comp_${idx}_${prov.id.hashCode()}",
                    name = "[${prov.category}] ${prov.filePath.substringAfterLast('/')}",
                    category = cat,
                    version = prov.matchedSymbolOrKey.take(60),
                    interfaceType = prov.category,
                    path = prov.filePath,
                    status = EvidenceStatus.CONFIRMED,
                    knowledgeLevel = KnowledgeLevel.FACT,
                    metadata = buildMap {
                        put("directory", prov.directory)
                        put("filePath", prov.filePath)
                        if (prov.importantContents.isNotEmpty()) {
                            put("contents", prov.importantContents.take(5).joinToString(" | ").take(240))
                        }
                    },
                    accessNote = prov.accessNote
                )
            }

        // Add DEX source extracts (SystemUI / services.jar / framework.jar) as SERVICE components with extracted source outline metadata
        baseline.dexSourceExtracts.forEachIndexed { idx, dex ->
            components += DiscoveredComponent(
                id = "dex_comp_${idx}_${dex.archivePath.hashCode()}",
                name = "[DEX] ${dex.archivePath.substringAfterLast('/')}",
                category = ComponentCategory.SERVICE,
                version = "${dex.matchedClasses.size} classes / ${dex.matchedMethods.size} methods",
                interfaceType = dex.targetHint,
                path = dex.archivePath,
                status = EvidenceStatus.CONFIRMED,
                knowledgeLevel = KnowledgeLevel.FACT,
                metadata = buildMap {
                    put("targetHint", dex.targetHint)
                    if (dex.matchedClasses.isNotEmpty()) put("classes", dex.matchedClasses.take(8).joinToString(" | ").take(260))
                    if (dex.matchedMethods.isNotEmpty()) put("methods", dex.matchedMethods.take(8).joinToString(" | ").take(260))
                    if (dex.matchedStrings.isNotEmpty()) put("strings", dex.matchedStrings.take(6).joinToString(" | ").take(240))
                }
            )
        }
    }

    private fun reconstructSessionFlow(
        liveLogcat: String,
        dmesgDelta: String,
        rootGranted: Boolean,
        language: AppLanguage
    ): List<SessionEvent> {
        val events = mutableListOf<SessionEvent>()

        if (!liveLogcat.isBlank() && !liveLogcat.startsWith("LOGCAT_UNAVAILABLE")) {
            val filteredLines = liveLogcat.lineSequence()
                .filter { liveLogFilterRegex.containsMatchIn(it) }
                .toList()

            filteredLines.takeLast(240).forEachIndexed { idx, line ->
                val lower = line.lowercase()
                val timestamp = line.take(18).trim()
                val phase = when {
                    lower.contains("enroll") || lower.contains("biometricprompt") -> "ENROLLMENT"
                    lower.contains("udfps") || lower.contains("fod") -> "FOD_OVERLAY"
                    lower.contains("hbm") || lower.contains("lhbm") || lower.contains("surfaceflinger") || lower.contains("dim") -> "DISPLAY_HBM"
                    lower.contains("avc:") -> "SELINUX"
                    lower.contains("hal") || lower.contains("goodix") || lower.contains("fpc") || lower.contains("silead") || lower.contains("onacquired") || lower.contains("onenrollresult") -> "HAL_EXEC"
                    else -> "BIOMETRIC_SVC"
                }

                val isBenignNoise = (lower.contains(" w ") || lower.contains("warning") ||
                    lower.contains("deprecated") || (lower.contains("not found") && !lower.contains("hal"))) &&
                    !lower.contains("fatal") && !lower.contains("deadobject") && !lower.contains("avc: denied")

                val isBlocking = (lower.contains("avc: denied") && (lower.contains("fingerprint") || lower.contains("fod") || lower.contains("hbm") || lower.contains("sysfs"))) ||
                    lower.contains("deadobjectexception") ||
                    lower.contains("error_hw_unavailable") ||
                    lower.contains("error_unable_to_process") ||
                    lower.contains("failed to open") ||
                    (lower.contains("permission denied") && (lower.contains("fod") || lower.contains("hbm") || lower.contains("fingerprint"))) ||
                    lower.contains("hal died") ||
                    lower.contains("null sensor")

                val isConfirmed = lower.contains("onacquired") ||
                    lower.contains("onenrollresult") ||
                    lower.contains("onfingerdown") ||
                    lower.contains("onfingerup") ||
                    lower.contains("hbm enable") ||
                    (lower.contains("lhbm") && !lower.contains("fail") && !lower.contains("error"))

                val status = when {
                    isBlocking -> EvidenceStatus.FAILED
                    isConfirmed -> EvidenceStatus.CONFIRMED
                    isBenignNoise -> EvidenceStatus.SUSPECT
                    else -> EvidenceStatus.OBSERVED
                }

                events += SessionEvent(
                    id = "evt_$idx",
                    timestamp = timestamp,
                    relativeMs = idx * 10L,
                    phase = phase,
                    component = extractTagFromLogLine(line),
                    summary = line.substringAfter(":", line).trim().take(160),
                    rawEvidence = line,
                    status = status,
                    knowledgeLevel = KnowledgeLevel.FACT,
                    isBenignWarning = isBenignNoise,
                    isBlockingFailure = isBlocking
                )
            }
        }

        if (dmesgDelta.isNotBlank() && !dmesgDelta.startsWith("DMESG_UNAVAILABLE") && !dmesgDelta.startsWith("NO_NEW_FOD")) {
            dmesgDelta.lines().filter { it.isNotBlank() }.take(80).forEachIndexed { idx, line ->
                val lower = line.lowercase()
                val isBlocking = lower.contains("avc: denied") || lower.contains("fail") || lower.contains("timeout")
                events += SessionEvent(
                    id = "dmesg_evt_$idx",
                    timestamp = "KERNEL",
                    relativeMs = 5000L + idx * 10L,
                    phase = if (lower.contains("avc:")) "SELINUX" else "KERNEL_DRIVER",
                    component = "dmesg",
                    summary = line.take(160),
                    rawEvidence = line,
                    status = if (isBlocking) EvidenceStatus.FAILED else EvidenceStatus.CONFIRMED,
                    knowledgeLevel = KnowledgeLevel.FACT,
                    isBenignWarning = false,
                    isBlockingFailure = isBlocking
                )
            }
        }

        if (events.isEmpty()) {
            events += SessionEvent(
                id = "flow_empty_scope",
                timestamp = "N/A",
                relativeMs = 0L,
                phase = "CAPTURE",
                component = if (rootGranted) "logcat" else "app_sandbox",
                summary = if (language == AppLanguage.FR) {
                    "Aucun événement FOD visible dans les tampons capturés."
                } else {
                    "No FOD events visible in captured buffers."
                },
                rawEvidence = liveLogcat.take(200),
                status = EvidenceStatus.UNKNOWN,
                knowledgeLevel = KnowledgeLevel.FACT
            )
        }

        return events
    }

    private fun extractTagFromLogLine(line: String): String {
        val parts = line.trim().split(Regex("\\s+"))
        return parts.drop(4).firstOrNull()?.substringBefore(":")?.take(40) ?: "system"
    }

    private fun evaluatePatchesRealEffect(
        patches: List<DetectedPatch>,
        sessionFlow: List<SessionEvent>,
        silentHalStall: Boolean,
        language: AppLanguage
    ): List<DetectedPatch> {
        val hasHbmEvent = sessionFlow.any { it.phase == "DISPLAY_HBM" && it.status == EvidenceStatus.CONFIRMED }
        val hasFodOverlay = sessionFlow.any { it.phase == "FOD_OVERLAY" && it.status == EvidenceStatus.CONFIRMED }
        val hasBlocking = silentHalStall || sessionFlow.any { it.isBlockingFailure }

        return patches.map { p ->
            val effect = when {
                p.name.contains("phh", true) && hasBlocking ->
                    if (language == AppLanguage.FR) "Présent mais n'empêche pas le blocage observé." else "Present, yet did not prevent the observed stall/break."
                p.name.contains("hbm", true) && hasHbmEvent ->
                    if (language == AppLanguage.FR) "Corrélé avec une activation HBM observée." else "Correlated with observed HBM activation."
                p.scope == "RRO Overlay" && p.rawValue == "ENABLED" && hasFodOverlay ->
                    if (language == AppLanguage.FR) "Overlay actif pendant la session FOD." else "Overlay active during FOD session."
                else -> p.realObservedEffect
            }
            p.copy(realObservedEffect = effect)
        }
    }

    private fun buildDependencyGraph(
        components: List<DiscoveredComponent>,
        sessionFlow: List<SessionEvent>,
        out: MutableList<DependencyEdge>
    ) {
        val bioSvc = components.firstOrNull { it.id == "svc_fingerprint" }
        val sfSvc = components.firstOrNull { it.id == "svc_surfaceflinger" }
        val hals = components.filter { it.category == ComponentCategory.HAL }
        val libs = components.filter { it.category == ComponentCategory.LIBRARY }
        val sysfs = components.filter { it.category == ComponentCategory.SYSFS_NODE }
        val overlays = components.filter { it.category == ComponentCategory.OVERLAY || it.category == ComponentCategory.PATCH }

        if (bioSvc != null) {
            hals.forEach { hal ->
                val halFailed = sessionFlow.any { it.isBlockingFailure && it.phase == "HAL_EXEC" }
                out += DependencyEdge(
                    fromId = bioSvc.id,
                    toId = hal.id,
                    relation = hal.interfaceType,
                    status = if (halFailed) EvidenceStatus.FAILED else hal.status,
                    note = "BiometricService <-> ${hal.name}"
                )
            }
            if (sfSvc != null) {
                val hbmFailed = sessionFlow.any { it.isBlockingFailure && it.phase == "DISPLAY_HBM" }
                out += DependencyEdge(
                    fromId = bioSvc.id,
                    toId = sfSvc.id,
                    relation = "Udfps / HBM Trigger",
                    status = if (hbmFailed) EvidenceStatus.FAILED else sfSvc.status,
                    note = "FOD illumination & touch sync"
                )
            }
        }

        hals.firstOrNull()?.let { primaryHal ->
            libs.take(6).forEach { lib ->
                out += DependencyEdge(
                    fromId = primaryHal.id,
                    toId = lib.id,
                    relation = "ELF DT_NEEDED",
                    status = lib.status,
                    note = lib.path
                )
            }
            sysfs.take(6).forEach { node ->
                out += DependencyEdge(
                    fromId = primaryHal.id,
                    toId = node.id,
                    relation = "sysfs / ioctl",
                    status = node.status,
                    note = node.path
                )
            }
        }

        if (sfSvc != null) {
            sysfs.take(4).forEach { node ->
                out += DependencyEdge(
                    fromId = sfSvc.id,
                    toId = node.id,
                    relation = "DRM / HBM Node",
                    status = node.status,
                    note = node.path
                )
            }
        }

        if (bioSvc != null) {
            overlays.take(5).forEach { ov ->
                out += DependencyEdge(
                    fromId = ov.id,
                    toId = bioSvc.id,
                    relation = "Config / Patch",
                    status = ov.status,
                    note = ov.name
                )
            }
        }
    }

    private fun buildFindings(
        baseline: BaselineProbeResult,
        components: List<DiscoveredComponent>,
        patches: List<DetectedPatch>,
        elfAnalyses: List<ElfBinaryAnalysis>,
        sessionFlow: List<SessionEvent>,
        fingerDownChain: List<FingerDownStep>,
        sysfsTransitions: List<SysfsTransition>,
        procLiveMaps: List<LiveProcessMapRecord>,
        findings: MutableList<InvestigationFinding>,
        language: AppLanguage
    ) {
        findings += InvestigationFinding(
            id = "find_env",
            title = if (language == AppLanguage.FR) "Empreinte matérielle & partitionnement" else "Hardware & Partition Baseline",
            detail = "Device=${baseline.environment.deviceModel}, GSI=${baseline.environment.isGsiSuspected}, SELinux=${baseline.environment.selinuxMode}, Root=${baseline.environment.rootGranted}",
            evidenceSnippet = "boot=${baseline.environment.bootSignature} | vendor=${baseline.environment.vendorFingerprint}",
            status = EvidenceStatus.CONFIRMED,
            knowledgeLevel = KnowledgeLevel.FACT
        )

        val changedSysfsCount = sysfsTransitions.count { it.changed }
        findings += InvestigationFinding(
            id = "find_finger_chain",
            title = if (language == AppLanguage.FR) "Chaîne d'exécution au poser du doigt (${fingerDownChain.size} étapes)" else "Finger-Down Execution Chain (${fingerDownChain.size} stages)",
            detail = "$changedSysfsCount/${sysfsTransitions.size} sysfs nodes transitioned during live session.",
            evidenceSnippet = fingerDownChain.joinToString("\n") { "[${it.status}] ${it.stage}: ${it.detail}" },
            status = if (fingerDownChain.any { it.status == EvidenceStatus.FAILED }) EvidenceStatus.FAILED else EvidenceStatus.CONFIRMED,
            knowledgeLevel = KnowledgeLevel.FACT
        )

        if (procLiveMaps.isNotEmpty()) {
            val newMapsTotal = procLiveMaps.sumOf { it.enrollmentNewMappedFiles.size }
            val newFdsTotal = procLiveMaps.sumOf { it.enrollmentNewFds.size }
            val topProcs = procLiveMaps.take(4).joinToString(" | ") { rec ->
                "${rec.processName}(pid=${rec.pid}): ${rec.matchedFodPaths.take(3).joinToString(",")}"
            }
            findings += InvestigationFinding(
                id = "find_proc_maps",
                title = if (language == AppLanguage.FR) "Processus FOD actifs (/proc/<pid>/maps & fd)" else "Live FOD Process Maps (/proc/<pid>/maps & fd)",
                detail = "${procLiveMaps.size} processus tracés | delta T0→T1 : +$newMapsTotal fichiers mappés, +$newFdsTotal descripteurs FD.",
                evidenceSnippet = topProcs.ifBlank { "Processes mapped" },
                status = EvidenceStatus.CONFIRMED,
                knowledgeLevel = KnowledgeLevel.FACT
            )
        }

        if (baseline.dexSourceExtracts.isNotEmpty()) {
            val totalCls = baseline.dexSourceExtracts.sumOf { it.matchedClasses.size }
            val totalMethods = baseline.dexSourceExtracts.sumOf { it.matchedMethods.size }
            findings += InvestigationFinding(
                id = "find_dex_sources",
                title = if (language == AppLanguage.FR) "Extraction code source DEX (${baseline.dexSourceExtracts.size} archives)" else "DEX Source Code Extract (${baseline.dexSourceExtracts.size} archives)",
                detail = "$totalCls classes FOD/UDFPS et $totalMethods signatures de méthodes extraites de SystemUI / Framework.",
                evidenceSnippet = baseline.dexSourceExtracts.take(3).joinToString(" | ") { "${it.archivePath}: ${it.matchedClasses.take(3).joinToString(",")}" },
                status = EvidenceStatus.CONFIRMED,
                knowledgeLevel = KnowledgeLevel.FACT
            )
        }

        val provenRros = baseline.overlayInspections.filter { it.fodRelevanceScore >= 40 || it.lookupWinners.isNotEmpty() }
        if (provenRros.isNotEmpty()) {
            findings += InvestigationFinding(
                id = "find_proven_rros",
                title = if (language == AppLanguage.FR) "Overlays RRO FOD prouvés par contenu ARSC/Lookup (${provenRros.size})" else "Content-Proven FOD RRO Overlays (${provenRros.size})",
                detail = provenRros.take(4).joinToString(" | ") { "${it.packageName} (score=${it.fodRelevanceScore}, apk=${it.apkPath})" },
                evidenceSnippet = provenRros.take(2).joinToString("\n") { ov ->
                    "${ov.packageName}: ${(ov.lookupWinners + ov.decodedArscEntries).take(4).joinToString("; ")}"
                },
                status = EvidenceStatus.CONFIRMED,
                knowledgeLevel = KnowledgeLevel.FACT
            )
        }

        val readableElfs = elfAnalyses.count { it.isReadable }
        findings += InvestigationFinding(
            id = "find_elf",
            title = if (language == AppLanguage.FR) "Couverture binaire ELF" else "ELF Binary Coverage",
            detail = "$readableElfs/${elfAnalyses.size} binaries readable for symbol & AArch64 disassembly.",
            evidenceSnippet = elfAnalyses.take(3).joinToString(" | ") { "${it.path}: ${it.fodSymbols.size} symbols" },
            status = if (readableElfs > 0) EvidenceStatus.CONFIRMED else EvidenceStatus.UNKNOWN,
            knowledgeLevel = KnowledgeLevel.FACT
        )

        findings += InvestigationFinding(
            id = "find_patches",
            title = if (language == AppLanguage.FR) "Inventaire complet des patchs/props/overlays" else "Complete Patch/Prop/Overlay Inventory",
            detail = "${patches.size} patchs, propriétés et overlays FOD/Treble recensés (${baseline.overlayInspections.size} overlays inspectés, ${baseline.fileProvenance.size} fichiers sources localisés).",
            evidenceSnippet = patches.take(5).joinToString(" ; ") { "${it.name}=${it.rawValue} [${it.target}]" },
            status = if (patches.isNotEmpty()) EvidenceStatus.CONFIRMED else EvidenceStatus.OBSERVED,
            knowledgeLevel = KnowledgeLevel.FACT
        )

        sessionFlow.filter { it.isBlockingFailure }.take(6).forEachIndexed { idx, evt ->
            findings += InvestigationFinding(
                id = "find_block_$idx",
                title = "${evt.phase}: ${evt.component}",
                detail = evt.summary,
                evidenceSnippet = evt.rawEvidence,
                status = EvidenceStatus.FAILED,
                knowledgeLevel = KnowledgeLevel.FACT,
                isBlocking = true
            )
        }

        sessionFlow.filter { it.isBenignWarning }.take(5).forEachIndexed { idx, evt ->
            findings += InvestigationFinding(
                id = "find_noise_$idx",
                title = "${evt.phase}: ${evt.component}",
                detail = evt.summary,
                evidenceSnippet = evt.rawEvidence,
                status = EvidenceStatus.SUSPECT,
                knowledgeLevel = KnowledgeLevel.CORRELATION,
                isBenignNoise = true
            )
        }

        if (baseline.environment.accessLimitations.isNotEmpty()) {
            findings += InvestigationFinding(
                id = "find_limits",
                title = if (language == AppLanguage.FR) "Restrictions d'accès signalées" else "Reported Access Restrictions",
                detail = "${baseline.environment.accessLimitations.size} sonde(s) limitée(s) par les permissions ou SELinux.",
                evidenceSnippet = baseline.environment.accessLimitations.joinToString("\n"),
                status = EvidenceStatus.UNKNOWN,
                knowledgeLevel = KnowledgeLevel.FACT
            )
        }
    }

    private fun parseProperties(raw: String): Map<String, String> {
        val map = LinkedHashMap<String, String>()
        val regex = Regex("^\\[(.+?)\\]: \\[(.*)\\]$")
        for (line in raw.lineSequence()) {
            val m = regex.matchEntire(line.trim()) ?: continue
            map[m.groupValues[1]] = m.groupValues[2]
        }
        return map
    }
}
