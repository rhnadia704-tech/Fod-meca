package com.example.engine

import com.example.model.DexMethodTrace
import com.example.model.DexSourceExtract
import java.io.ByteArrayInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipInputStream

data class ArscEntryRecord(
    val typeName: String,
    val keyName: String,
    val valueText: String,
    val packageName: String = "",
    val resId: Int = 0
)

data class DecodedArscResult(
    val packageNames: List<String>,
    val allFodOrConfigEntries: List<ArscEntryRecord>,
    val discoveredResourceKeys: List<Pair<String, String>>,
    val totalEntriesScanned: Int
)

object BinarySourceDecoder {

    private val fodKeywordRegex = Regex(
        "(fod|udfps|fingerprint|biometric|hbm|lhbm|dimlayer|doze|burn_in|illumination|optical|ultrasonic|goodix|fpc|silead|focal|egis|synaptics|disp_param|touch_dev|xiaomi\\.fingerprint|oplus\\.biometrics|phh|treble|auth|sensor)",
        RegexOption.IGNORE_CASE
    )

    private val fodDexMethodOrClassRegex = Regex(
        "(udfps|fod|fingerprint|biometric|hbm|lhbm|authcontroller|doze|displaymode|brightness|extcmd|disp_param|goodix|xiaomi|oplus|phh|treble|onfingerdown|onfingerup|onacquired|onenroll)",
        RegexOption.IGNORE_CASE
    )

    // -------------------------------------------------------------------------
    // 1. RES_STRING_POOL_TYPE (0x0001) reader
    // -------------------------------------------------------------------------

    fun parseStringPool(bytes: ByteArray, chunkStart: Int, limit: Int): List<String> {
        if (chunkStart < 0 || chunkStart + 28 > limit || limit > bytes.size) return emptyList()
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val type = buf.getShort(chunkStart).toInt() and 0xFFFF
        val headerSize = buf.getShort(chunkStart + 2).toInt() and 0xFFFF
        val chunkSize = buf.getInt(chunkStart + 4)
        if (type != 0x0001 || headerSize < 28 || chunkSize < 28 || chunkStart + chunkSize > limit) {
            return emptyList()
        }

        val stringCount = buf.getInt(chunkStart + 8)
        val flags = buf.getInt(chunkStart + 16)
        val stringsStart = buf.getInt(chunkStart + 20)
        val isUtf8 = (flags and 0x100) != 0

        val tableBase = chunkStart + headerSize
        val poolDataBase = chunkStart + stringsStart
        val chunkEnd = chunkStart + chunkSize
        if (stringCount !in 1..100_000) return emptyList()
        if (tableBase + stringCount.toLong() * 4L > chunkEnd) return emptyList()
        if (poolDataBase !in chunkStart until chunkEnd) return emptyList()

        val out = ArrayList<String>(stringCount)
        for (i in 0 until stringCount) {
            val strOffset = buf.getInt(tableBase + i * 4)
            val absPos = poolDataBase + strOffset
            val s = if (absPos in poolDataBase until chunkEnd) {
                if (isUtf8) decodeUtf8PoolString(bytes, absPos, chunkEnd)
                else decodeUtf16PoolString(bytes, absPos, chunkEnd)
            } else {
                ""
            }
            out += s
        }
        return out
    }

    private fun decodeUtf8PoolString(bytes: ByteArray, offset: Int, limit: Int): String {
        var p = offset
        if (p >= limit) return ""
        val first = bytes[p++].toInt() and 0xFF
        if ((first and 0x80) != 0 && p < limit) p++
        if (p >= limit) return ""
        var byteLen = bytes[p++].toInt() and 0xFF
        if ((byteLen and 0x80) != 0 && p < limit) {
            byteLen = ((byteLen and 0x7F) shl 8) or (bytes[p++].toInt() and 0xFF)
        }
        if (byteLen <= 0 || p + byteLen > limit || byteLen > 4096) return ""
        return String(bytes, p, byteLen, Charsets.UTF_8)
    }

    private fun decodeUtf16PoolString(bytes: ByteArray, offset: Int, limit: Int): String {
        var p = offset
        if (p + 2 > limit) return ""
        var charLen = (bytes[p].toInt() and 0xFF) or ((bytes[p + 1].toInt() and 0xFF) shl 8)
        p += 2
        if ((charLen and 0x8000) != 0 && p + 2 <= limit) {
            val low = (bytes[p].toInt() and 0xFF) or ((bytes[p + 1].toInt() and 0xFF) shl 8)
            charLen = ((charLen and 0x7FFF) shl 16) or low
            p += 2
        }
        val byteLen = charLen * 2
        if (byteLen <= 0 || p + byteLen > limit || charLen > 2048) return ""
        return String(bytes, p, byteLen, Charsets.UTF_16LE)
    }

    // -------------------------------------------------------------------------
    // 2. Binary AXML (RES_XML_TYPE = 0x0003) -> Readable Pseudo-XML Decoder
    // -------------------------------------------------------------------------

    fun decodeBinaryXmlToPseudoXml(bytes: ByteArray, maxLines: Int = 120): String {
        if (bytes.size < 16) return ""
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val rootType = buf.getShort(0).toInt() and 0xFFFF
        if (rootType != 0x0003) return ""
        val rootHeaderSize = buf.getShort(2).toInt() and 0xFFFF
        val rootChunkSize = buf.getInt(4).coerceAtMost(bytes.size)
        if (rootHeaderSize < 8 || rootChunkSize < 16) return ""

        var stringPool: List<String> = emptyList()
        var resourceIds: IntArray = IntArray(0)
        val nsPrefixes = LinkedHashMap<String, String>()
        val lines = ArrayList<String>()
        var indent = 0
        val openStack = ArrayDeque<String>()

        var pos = rootHeaderSize
        while (pos + 8 <= rootChunkSize && lines.size < maxLines) {
            val type = buf.getShort(pos).toInt() and 0xFFFF
            val headerSize = buf.getShort(pos + 2).toInt() and 0xFFFF
            val chunkSize = buf.getInt(pos + 4)
            if (chunkSize < 8 || headerSize < 8 || pos + chunkSize > rootChunkSize) break

            when (type) {
                0x0001 -> { // RES_STRING_POOL_TYPE
                    stringPool = parseStringPool(bytes, pos, pos + chunkSize)
                }
                0x0180 -> { // RES_XML_RESOURCE_MAP_TYPE
                    val count = (chunkSize - headerSize) / 4
                    if (count in 1..10_000) {
                        resourceIds = IntArray(count) { i ->
                            buf.getInt(pos + headerSize + i * 4)
                        }
                    }
                }
                0x0100 -> { // RES_XML_START_NAMESPACE_TYPE
                    if (pos + headerSize + 8 <= pos + chunkSize) {
                        val prefixIdx = buf.getInt(pos + headerSize)
                        val uriIdx = buf.getInt(pos + headerSize + 4)
                        val prefix = stringPool.getOrNull(prefixIdx).orEmpty()
                        val uri = stringPool.getOrNull(uriIdx).orEmpty()
                        if (uri.isNotBlank()) nsPrefixes[uri] = prefix.ifBlank { "android" }
                    }
                }
                0x0102 -> { // RES_XML_START_ELEMENT_TYPE
                    val extBase = pos + headerSize
                    if (extBase + 20 <= pos + chunkSize) {
                        val nsIdx = buf.getInt(extBase)
                        val nameIdx = buf.getInt(extBase + 4)
                        val attrStart = buf.getShort(extBase + 8).toInt() and 0xFFFF
                        val attrSize = (buf.getShort(extBase + 10).toInt() and 0xFFFF).coerceAtLeast(20)
                        val attrCount = (buf.getShort(extBase + 12).toInt() and 0xFFFF).coerceAtMost(64)

                        val elemNs = stringPool.getOrNull(nsIdx)
                        val elemName = stringPool.getOrNull(nameIdx)?.ifBlank { "node" } ?: "node"
                        val fullTag = if (!elemNs.isNullOrBlank()) {
                            "${nsPrefixes[elemNs] ?: elemNs.substringAfterLast('/')}:$elemName"
                        } else elemName

                        val attrs = mutableListOf<String>()
                        val attrsBase = extBase + attrStart
                        for (a in 0 until attrCount) {
                            val aOff = attrsBase + a * attrSize
                            if (aOff + 20 > pos + chunkSize) break
                            val aNsIdx = buf.getInt(aOff)
                            val aNameIdx = buf.getInt(aOff + 4)
                            val aRawValIdx = buf.getInt(aOff + 8)
                            val aValType = bytes[aOff + 15].toInt() and 0xFF
                            val aValData = buf.getInt(aOff + 16)

                            val aNameRaw = stringPool.getOrNull(aNameIdx)?.takeIf { it.isNotBlank() }
                                ?: resourceIds.getOrNull(aNameIdx)?.let { "attr_0x${it.toUInt().toString(16)}" }
                                ?: "attr$a"
                            val aNs = if (aNsIdx >= 0) stringPool.getOrNull(aNsIdx) else null
                            val aPrefix = when {
                                aNs == null -> ""
                                nsPrefixes.containsKey(aNs) -> "${nsPrefixes[aNs]}:"
                                aNs.contains("android") -> "android:"
                                else -> ""
                            }

                            val aValueStr = if (aRawValIdx >= 0 && aValType == 0x03) {
                                stringPool.getOrNull(aRawValIdx) ?: "@str/$aRawValIdx"
                            } else {
                                formatResValue(aValType, aValData, stringPool)
                            }
                            attrs += "$aPrefix$aNameRaw=\"$aValueStr\""
                        }

                        val pad = "  ".repeat(indent.coerceAtMost(10))
                        val attrStr = if (attrs.isEmpty()) "" else " " + attrs.joinToString(" ")
                        lines += "$pad<$fullTag$attrStr>"
                        openStack.addLast(fullTag)
                        indent++
                    }
                }
                0x0103 -> { // RES_XML_END_ELEMENT_TYPE
                    val closed = if (openStack.isNotEmpty()) openStack.removeLast() else "node"
                    if (indent > 0) indent--
                    val pad = "  ".repeat(indent.coerceAtMost(10))
                    // Compact empty element on single line if previous line was its open tag
                    val last = lines.lastOrNull()
                    if (last != null && last.trimStart().startsWith("<$closed") && last.endsWith(">") && !last.endsWith("/>")) {
                        lines[lines.lastIndex] = last.dropLast(1) + " />"
                    } else {
                        lines += "$pad</$closed>"
                    }
                }
            }
            pos += chunkSize
        }
        return lines.joinToString("\n")
    }

    // -------------------------------------------------------------------------
    // 3. resources.arsc (RES_TABLE_TYPE = 0x0002) -> Resource Key/Value Decoder
    // -------------------------------------------------------------------------

    fun buildArscIdLookupTable(bytes: ByteArray): Map<Int, ArscEntryRecord> {
        val map = HashMap<Int, ArscEntryRecord>(2048)
        decodeArscInternal(bytes, maxFodEntries = 1, onlyFodFilter = false, outIdMap = map)
        return map
    }

    fun decodeArscResourceEntries(bytes: ByteArray, maxFodEntries: Int = 120): DecodedArscResult =
        decodeArscInternal(bytes, maxFodEntries = maxFodEntries, onlyFodFilter = true, outIdMap = null)

    private fun decodeArscInternal(
        bytes: ByteArray,
        maxFodEntries: Int,
        onlyFodFilter: Boolean,
        outIdMap: MutableMap<Int, ArscEntryRecord>?
    ): DecodedArscResult {
        if (bytes.size < 16) {
            return DecodedArscResult(emptyList(), emptyList(), emptyList(), 0)
        }
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val rootType = buf.getShort(0).toInt() and 0xFFFF
        val rootHeaderSize = buf.getShort(2).toInt() and 0xFFFF
        val rootSize = buf.getInt(4).coerceAtMost(bytes.size)
        if (rootType != 0x0002 || rootHeaderSize < 12 || rootSize < 16) {
            return DecodedArscResult(emptyList(), emptyList(), emptyList(), 0)
        }

        var globalPool: List<String> = emptyList()
        val packageNames = mutableListOf<String>()
        val results = mutableListOf<ArscEntryRecord>()
        val discoveredKeys = mutableListOf<Pair<String, String>>()
        var totalScanned = 0

        var pos = rootHeaderSize
        while (pos + 8 <= rootSize) {
            val type = buf.getShort(pos).toInt() and 0xFFFF
            val headerSize = buf.getShort(pos + 2).toInt() and 0xFFFF
            val chunkSize = buf.getInt(pos + 4)
            if (chunkSize < 8 || headerSize < 8 || pos + chunkSize > rootSize) break

            when (type) {
                0x0001 -> {
                    globalPool = parseStringPool(bytes, pos, pos + chunkSize)
                }
                0x0200 -> { // RES_TABLE_PACKAGE_TYPE
                    val pkgEnd = pos + chunkSize
                    val pkgId = if (pos + 12 <= pkgEnd) buf.getInt(pos + 8) and 0xFF else 0x7F
                    val pkgName = if (pos + 268 <= pkgEnd) readFixedUtf16CString(bytes, pos + 12, 128) else ""
                    if (pkgName.isNotBlank()) packageNames += pkgName
                    val typeStringsRel = if (pos + 272 <= pkgEnd) buf.getInt(pos + 268) else 0
                    val keyStringsRel = if (pos + 280 <= pkgEnd) buf.getInt(pos + 276) else 0
                    val typeIdOffset = if (headerSize >= 288 && pos + 288 <= pkgEnd) buf.getInt(pos + 284) else 0

                    val typePool = if (typeStringsRel in headerSize until chunkSize) {
                        parseStringPool(bytes, pos + typeStringsRel, pkgEnd)
                    } else emptyList()
                    val keyPool = if (keyStringsRel in headerSize until chunkSize) {
                        parseStringPool(bytes, pos + keyStringsRel, pkgEnd)
                    } else emptyList()

                    var cPos = pos + headerSize
                    while (cPos + 8 <= pkgEnd && (!onlyFodFilter || results.size < maxFodEntries * 2)) {
                        val cType = buf.getShort(cPos).toInt() and 0xFFFF
                        val cHeader = buf.getShort(cPos + 2).toInt() and 0xFFFF
                        val cSize = buf.getInt(cPos + 4)
                        if (cSize < 8 || cHeader < 8 || cPos + cSize > pkgEnd) break

                        if (cType == 0x0201 && cPos + 20 <= pkgEnd) { // RES_TABLE_TYPE_TYPE
                            val cEnd = cPos + cSize
                            val typeId = (bytes[cPos + 8].toInt() and 0xFF) + typeIdOffset
                            val typeFlags = bytes[cPos + 9].toInt() and 0xFF
                            val entryCount = buf.getInt(cPos + 12)
                            val entriesStart = buf.getInt(cPos + 16)
                            val typeName = typePool.getOrNull((bytes[cPos + 8].toInt() and 0xFF) - 1) ?: "type_$typeId"
                            val entriesBase = cPos + entriesStart
                            val offsetsBase = cPos + cHeader
                            val isSparse = (typeFlags and 0x01) != 0

                            if (entryCount in 1..20_000 && entriesBase in cPos until cEnd) {
                                for (i in 0 until entryCount) {
                                    var actualEntryId = i
                                    val entryOffset = if (isSparse) {
                                        val offPos = offsetsBase + i * 4
                                        if (offPos + 4 > cEnd) break
                                        actualEntryId = buf.getShort(offPos).toInt() and 0xFFFF
                                        val offDiv4 = buf.getShort(offPos + 2).toInt() and 0xFFFF
                                        if (offDiv4 == 0xFFFF) -1 else offDiv4 * 4
                                    } else {
                                        val offPos = offsetsBase + i * 4
                                        if (offPos + 4 > cEnd) break
                                        buf.getInt(offPos)
                                    }
                                    if (entryOffset < 0) continue

                                    val ePos = entriesBase + entryOffset
                                    if (ePos + 8 > cEnd) continue

                                    totalScanned++
                                    val firstU16 = buf.getShort(ePos).toInt() and 0xFFFF
                                    val entryFlags = buf.getShort(ePos + 2).toInt() and 0xFFFF
                                    val isCompact = (entryFlags and 0x0008) != 0
                                    val isComplex = !isCompact && (entryFlags and 0x0001) != 0

                                    val keyName: String
                                    val decodedValue: String

                                    if (isCompact) {
                                        val keyIdx = firstU16
                                        keyName = keyPool.getOrNull(keyIdx) ?: continue
                                        val valType = (entryFlags ushr 8) and 0xFF
                                        val valData = buf.getInt(ePos + 4)
                                        decodedValue = formatResValue(valType, valData, globalPool)
                                    } else {
                                        val entrySize = firstU16.coerceAtLeast(8)
                                        val keyIdx = buf.getInt(ePos + 4)
                                        keyName = keyPool.getOrNull(keyIdx) ?: continue
                                        if (!isComplex) {
                                            val valPos = ePos + entrySize
                                            if (valPos + 8 > cEnd) continue
                                            val valType = bytes[valPos + 3].toInt() and 0xFF
                                            val valData = buf.getInt(valPos + 4)
                                            decodedValue = formatResValue(valType, valData, globalPool)
                                        } else {
                                            if (ePos + 16 > cEnd) continue
                                            val mapCount = buf.getInt(ePos + 12).coerceIn(0, 32)
                                            val items = ArrayList<String>(mapCount)
                                            var mPos = ePos + entrySize.coerceAtLeast(16)
                                            for (m in 0 until mapCount) {
                                                if (mPos + 12 > cEnd) break
                                                val valType = bytes[mPos + 7].toInt() and 0xFF
                                                val valData = buf.getInt(mPos + 8)
                                                items += formatResValue(valType, valData, globalPool)
                                                mPos += 12
                                            }
                                            decodedValue = items.joinToString(", ", "[", "]")
                                        }
                                    }

                                    val resId = (pkgId shl 24) or ((typeId and 0xFF) shl 16) or (actualEntryId and 0xFFFF)
                                    val rec = ArscEntryRecord(
                                        typeName = typeName,
                                        keyName = keyName,
                                        valueText = decodedValue,
                                        packageName = pkgName,
                                        resId = resId
                                    )
                                    outIdMap?.putIfAbsent(resId, rec)

                                    if (onlyFodFilter) {
                                        val isFodRelevant = fodKeywordRegex.containsMatchIn(keyName) ||
                                            fodKeywordRegex.containsMatchIn(decodedValue) ||
                                            keyName.startsWith("config_")
                                        if (isFodRelevant) {
                                            discoveredKeys += typeName to keyName
                                            results += rec
                                        }
                                    }
                                }
                            }
                        }
                        cPos += cSize
                    }
                }
            }
            pos += chunkSize
        }

        val prioritized = results
            .distinctBy { "${it.typeName}/${it.keyName}=${it.valueText}" }
            .sortedByDescending { fodKeywordRegex.containsMatchIn(it.keyName) }
            .take(maxFodEntries)

        return DecodedArscResult(
            packageNames = packageNames.distinct(),
            allFodOrConfigEntries = prioritized,
            discoveredResourceKeys = discoveredKeys.distinct().take(120),
            totalEntriesScanned = totalScanned
        )
    }

    private fun readFixedUtf16CString(bytes: ByteArray, offset: Int, maxChars: Int): String {
        val sb = StringBuilder()
        for (i in 0 until maxChars) {
            val p = offset + i * 2
            if (p + 2 > bytes.size) break
            val ch = (bytes[p].toInt() and 0xFF) or ((bytes[p + 1].toInt() and 0xFF) shl 8)
            if (ch == 0) break
            sb.append(ch.toChar())
        }
        return sb.toString()
    }

    private fun formatResValue(dataType: Int, data: Int, globalPool: List<String>): String {
        return when (dataType) {
            0x00 -> "null"
            0x01 -> "@0x${data.toUInt().toString(16)}"
            0x02 -> "?0x${data.toUInt().toString(16)}"
            0x03 -> globalPool.getOrNull(data) ?: "@str/$data"
            0x04 -> java.lang.Float.intBitsToFloat(data).toString()
            0x05 -> {
                val unit = when (data and 0x0F) {
                    0 -> "px"
                    1 -> "dp"
                    2 -> "sp"
                    3 -> "pt"
                    4 -> "in"
                    5 -> "mm"
                    else -> "dim"
                }
                val mantissa = data ushr 8
                val radix = (data ushr 4) and 0x03
                val value = when (radix) {
                    0 -> mantissa.toFloat()
                    1 -> mantissa / 128f
                    2 -> mantissa / 32768f
                    else -> mantissa / 8388608f
                }
                "$value$unit"
            }
            0x10 -> data.toString()
            0x11 -> "0x${data.toUInt().toString(16)}"
            0x12 -> (data != 0).toString()
            0x1C, 0x1D, 0x1E, 0x1F -> "#${data.toUInt().toString(16).padStart(8, '0')}"
            else -> "type($dataType)=0x${data.toUInt().toString(16)}"
        }
    }

    // -------------------------------------------------------------------------
    // 4. Multi-DEX (APK/JAR classes*.dex + VDEX/ODEX) Source & Bytecode Extractor
    // -------------------------------------------------------------------------

    fun extractFodDexSourcesFromArchive(
        archiveBytes: ByteArray,
        archivePath: String,
        targetHint: String,
        arscIdMap: Map<Int, ArscEntryRecord> = emptyMap()
    ): DexSourceExtract? {
        val matchedClasses = linkedSetOf<String>()
        val matchedMethods = linkedSetOf<String>()
        val matchedStrings = linkedSetOf<String>()
        val classBodyOutlines = linkedMapOf<String, MutableList<String>>()
        val classHeaders = linkedMapOf<String, String>()
        val methodTraces = mutableListOf<DexMethodTrace>()
        val referencedResIds = linkedSetOf<Int>()
        val resolvedResKeys = linkedSetOf<String>()

        runCatching {
            ZipInputStream(ByteArrayInputStream(archiveBytes)).use { zip ->
                var entry = zip.nextEntry
                while (entry != null) {
                    val name = entry.name
                    if (!entry.isDirectory && name.startsWith("classes") && name.endsWith(".dex")) {
                        val dexBytes = zip.readBytes()
                        DalvikBytecodeDecoder.parseSingleDexWithBytecode(
                            dexBytes = dexBytes,
                            arscIdMap = arscIdMap,
                            matchedClasses = matchedClasses,
                            matchedMethods = matchedMethods,
                            matchedStrings = matchedStrings,
                            classHeaders = classHeaders,
                            classBodyOutlines = classBodyOutlines,
                            methodTraces = methodTraces,
                            referencedResIds = referencedResIds,
                            resolvedResourceKeys = resolvedResKeys
                        )
                    }
                    zip.closeEntry()
                    entry = zip.nextEntry
                }
            }
        }

        return finalizeDexSourceExtract(
            archivePath = archivePath,
            targetHint = targetHint,
            containerType = "APK/JAR",
            matchedClasses = matchedClasses,
            matchedMethods = matchedMethods,
            matchedStrings = matchedStrings,
            classHeaders = classHeaders,
            classBodyOutlines = classBodyOutlines,
            methodTraces = methodTraces,
            referencedResIds = referencedResIds,
            resolvedResKeys = resolvedResKeys
        )
    }

    fun extractFodDexSourcesFromVdexOrOat(
        containerBytes: ByteArray,
        containerPath: String,
        targetHint: String,
        arscIdMap: Map<Int, ArscEntryRecord> = emptyMap()
    ): DexSourceExtract? {
        val dexSlices = DalvikBytecodeDecoder.extractStandardDexSlicesFromVdexOrOat(containerBytes)
        if (dexSlices.isEmpty()) return null

        val matchedClasses = linkedSetOf<String>()
        val matchedMethods = linkedSetOf<String>()
        val matchedStrings = linkedSetOf<String>()
        val classBodyOutlines = linkedMapOf<String, MutableList<String>>()
        val classHeaders = linkedMapOf<String, String>()
        val methodTraces = mutableListOf<DexMethodTrace>()
        val referencedResIds = linkedSetOf<Int>()
        val resolvedResKeys = linkedSetOf<String>()

        dexSlices.forEach { slice ->
            DalvikBytecodeDecoder.parseSingleDexWithBytecode(
                dexBytes = slice,
                arscIdMap = arscIdMap,
                matchedClasses = matchedClasses,
                matchedMethods = matchedMethods,
                matchedStrings = matchedStrings,
                classHeaders = classHeaders,
                classBodyOutlines = classBodyOutlines,
                methodTraces = methodTraces,
                referencedResIds = referencedResIds,
                resolvedResourceKeys = resolvedResKeys
            )
        }

        return finalizeDexSourceExtract(
            archivePath = containerPath,
            targetHint = targetHint,
            containerType = "VDEX/ODEX (${dexSlices.size} DEX)",
            matchedClasses = matchedClasses,
            matchedMethods = matchedMethods,
            matchedStrings = matchedStrings,
            classHeaders = classHeaders,
            classBodyOutlines = classBodyOutlines,
            methodTraces = methodTraces,
            referencedResIds = referencedResIds,
            resolvedResKeys = resolvedResKeys
        )
    }

    private fun finalizeDexSourceExtract(
        archivePath: String,
        targetHint: String,
        containerType: String,
        matchedClasses: Set<String>,
        matchedMethods: Set<String>,
        matchedStrings: Set<String>,
        classHeaders: Map<String, String>,
        classBodyOutlines: Map<String, List<String>>,
        methodTraces: List<DexMethodTrace>,
        referencedResIds: Set<Int>,
        resolvedResKeys: Set<String>
    ): DexSourceExtract? {
        if (matchedClasses.isEmpty() && matchedMethods.isEmpty() && matchedStrings.isEmpty() && methodTraces.isEmpty()) {
            return null
        }

        val prioritizedTraces = methodTraces
            .distinctBy { it.fqMethod }
            .sortedByDescending { (it.resolvedResKeys.size * 4) + (it.referencedStrings.size * 3) + it.invokedMethods.size }
            .take(30)

        val pseudoSummary = buildString {
            appendLine("// [$containerType] Extracted Dalvik Bytecode & Call Graph from $archivePath")
            if (resolvedResKeys.isNotEmpty()) {
                appendLine("// Exact R.id Resource Keys Referenced in Bytecode:")
                resolvedResKeys.take(20).forEach { k -> appendLine("//   R -> $k") }
            }
            if (prioritizedTraces.isNotEmpty()) {
                appendLine("// Decoded Dalvik Bytecode Call Graph (code_item):")
                prioritizedTraces.take(14).forEach { tr ->
                    if (tr.bytecodeSnippet.isNotBlank()) {
                        appendLine(tr.bytecodeSnippet)
                    }
                }
            }
            classHeaders.entries.take(20).forEach { (cls, hdr) ->
                appendLine("$hdr {")
                classBodyOutlines[cls].orEmpty().take(10).forEach { m ->
                    appendLine("    $m")
                }
                appendLine("}")
            }
            if (matchedStrings.isNotEmpty()) {
                appendLine("// Key SYSFS / PROP / AIDL / HIDL Strings Referenced:")
                matchedStrings.take(24).forEach { s -> appendLine("//   \"$s\"") }
            }
        }.trim()

        return DexSourceExtract(
            archivePath = archivePath,
            targetHint = targetHint,
            matchedClasses = matchedClasses.take(60),
            matchedMethods = matchedMethods.take(120),
            matchedStrings = matchedStrings.take(80),
            sourcePseudoSummary = pseudoSummary,
            containerType = containerType,
            methodTraces = prioritizedTraces,
            referencedResIds = referencedResIds.take(40),
            resolvedResourceKeys = resolvedResKeys.take(50)
        )
    }

    internal fun parseSingleDexFodContent(
        dexBytes: ByteArray,
        matchedClasses: MutableSet<String> = linkedSetOf(),
        matchedMethods: MutableSet<String> = linkedSetOf(),
        matchedStrings: MutableSet<String> = linkedSetOf(),
        classHeaders: MutableMap<String, String> = linkedMapOf(),
        classBodyOutlines: MutableMap<String, MutableList<String>> = linkedMapOf()
    ) {
        DalvikBytecodeDecoder.parseSingleDexWithBytecode(
            dexBytes = dexBytes,
            arscIdMap = emptyMap(),
            matchedClasses = matchedClasses,
            matchedMethods = matchedMethods,
            matchedStrings = matchedStrings,
            classHeaders = classHeaders,
            classBodyOutlines = classBodyOutlines
        )
    }

    internal fun formatDexDescriptor(desc: String): String = DalvikBytecodeDecoder.formatDexDescriptor(desc)
}
