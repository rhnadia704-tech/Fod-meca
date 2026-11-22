package com.example.engine

import com.example.model.DexSourceExtract
import java.io.ByteArrayInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipInputStream

data class ArscEntryRecord(
    val typeName: String,
    val keyName: String,
    val valueText: String,
    val packageName: String = ""
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

    fun decodeArscResourceEntries(bytes: ByteArray, maxFodEntries: Int = 120): DecodedArscResult {
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
                    val pkgName = if (pos + 268 <= pkgEnd) readFixedUtf16CString(bytes, pos + 12, 128) else ""
                    if (pkgName.isNotBlank()) packageNames += pkgName
                    val typeStringsRel = if (pos + 272 <= pkgEnd) buf.getInt(pos + 268) else 0
                    val keyStringsRel = if (pos + 280 <= pkgEnd) buf.getInt(pos + 276) else 0

                    val typePool = if (typeStringsRel in headerSize until chunkSize) {
                        parseStringPool(bytes, pos + typeStringsRel, pkgEnd)
                    } else emptyList()
                    val keyPool = if (keyStringsRel in headerSize until chunkSize) {
                        parseStringPool(bytes, pos + keyStringsRel, pkgEnd)
                    } else emptyList()

                    var cPos = pos + headerSize
                    while (cPos + 8 <= pkgEnd && results.size < maxFodEntries * 2) {
                        val cType = buf.getShort(cPos).toInt() and 0xFFFF
                        val cHeader = buf.getShort(cPos + 2).toInt() and 0xFFFF
                        val cSize = buf.getInt(cPos + 4)
                        if (cSize < 8 || cHeader < 8 || cPos + cSize > pkgEnd) break

                        if (cType == 0x0201 && cPos + 20 <= pkgEnd) { // RES_TABLE_TYPE_TYPE
                            val cEnd = cPos + cSize
                            val typeId = bytes[cPos + 8].toInt() and 0xFF
                            val typeFlags = bytes[cPos + 9].toInt() and 0xFF
                            val entryCount = buf.getInt(cPos + 12)
                            val entriesStart = buf.getInt(cPos + 16)
                            val typeName = typePool.getOrNull(typeId - 1) ?: "type_$typeId"
                            val entriesBase = cPos + entriesStart
                            val offsetsBase = cPos + cHeader
                            val isSparse = (typeFlags and 0x01) != 0

                            if (entryCount in 1..20_000 && entriesBase in cPos until cEnd) {
                                for (i in 0 until entryCount) {
                                    val entryOffset = if (isSparse) {
                                        val offPos = offsetsBase + i * 4
                                        if (offPos + 4 > cEnd) break
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
                                            val mapCountPos = ePos + entrySize
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

                                    val isFodRelevant = fodKeywordRegex.containsMatchIn(keyName) ||
                                        fodKeywordRegex.containsMatchIn(decodedValue) ||
                                        keyName.startsWith("config_")
                                    if (isFodRelevant) {
                                        discoveredKeys += typeName to keyName
                                        results += ArscEntryRecord(
                                            typeName = typeName,
                                            keyName = keyName,
                                            valueText = decodedValue,
                                            packageName = pkgName
                                        )
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
    // 4. Multi-DEX (classes*.dex, DEX 035-041) Source-Level Extractor
    // -------------------------------------------------------------------------

    fun extractFodDexSourcesFromArchive(
        archiveBytes: ByteArray,
        archivePath: String,
        targetHint: String
    ): DexSourceExtract? {
        val matchedClasses = linkedSetOf<String>()
        val matchedMethods = linkedSetOf<String>()
        val matchedStrings = linkedSetOf<String>()
        val classBodyOutlines = linkedMapOf<String, MutableList<String>>()
        val classHeaders = linkedMapOf<String, String>()

        runCatching {
            ZipInputStream(ByteArrayInputStream(archiveBytes)).use { zip ->
                var entry = zip.nextEntry
                while (entry != null) {
                    val name = entry.name
                    if (!entry.isDirectory && name.startsWith("classes") && name.endsWith(".dex")) {
                        val dexBytes = zip.readBytes()
                        parseSingleDexFodContent(
                            dexBytes = dexBytes,
                            matchedClasses = matchedClasses,
                            matchedMethods = matchedMethods,
                            matchedStrings = matchedStrings,
                            classHeaders = classHeaders,
                            classBodyOutlines = classBodyOutlines
                        )
                    }
                    zip.closeEntry()
                    entry = zip.nextEntry
                }
            }
        }

        if (matchedClasses.isEmpty() && matchedMethods.isEmpty() && matchedStrings.isEmpty()) {
            return null
        }

        val pseudoSummary = buildString {
            appendLine("// Extracted DEX FOD/UDFPS Source Outline from $archivePath")
            classHeaders.entries.take(28).forEach { (cls, hdr) ->
                appendLine("$hdr {")
                classBodyOutlines[cls].orEmpty().take(12).forEach { m ->
                    appendLine("    $m")
                }
                appendLine("}")
            }
            if (matchedStrings.isNotEmpty()) {
                appendLine("// Key SYSFS / PROP / AIDL / HIDL Strings Referenced:")
                matchedStrings.take(30).forEach { s -> appendLine("//   \"$s\"") }
            }
        }.trim()

        return DexSourceExtract(
            archivePath = archivePath,
            targetHint = targetHint,
            matchedClasses = matchedClasses.take(60),
            matchedMethods = matchedMethods.take(120),
            matchedStrings = matchedStrings.take(80),
            sourcePseudoSummary = pseudoSummary
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
        if (dexBytes.size < 112) return
        if (dexBytes[0] != 'd'.code.toByte() || dexBytes[1] != 'e'.code.toByte() ||
            dexBytes[2] != 'x'.code.toByte() || dexBytes[3] != '\n'.code.toByte()
        ) return

        val buf = ByteBuffer.wrap(dexBytes).order(ByteOrder.LITTLE_ENDIAN)
        val stringIdsSize = buf.getInt(56)
        val stringIdsOff = buf.getInt(60)
        val typeIdsSize = buf.getInt(64)
        val typeIdsOff = buf.getInt(68)
        val protoIdsSize = buf.getInt(72)
        val protoIdsOff = buf.getInt(76)
        val methodIdsSize = buf.getInt(88)
        val methodIdsOff = buf.getInt(92)
        val classDefsSize = buf.getInt(96)
        val classDefsOff = buf.getInt(100)

        if (stringIdsSize !in 1..250_000 || stringIdsOff < 112 || stringIdsOff + stringIdsSize * 4 > dexBytes.size) return
        if (typeIdsSize !in 0..100_000 || typeIdsOff + typeIdsSize * 4 > dexBytes.size) return

        val stringCache = HashMap<Int, String>(4096)
        fun getString(idx: Int): String {
            if (idx !in 0 until stringIdsSize) return ""
            return stringCache.getOrPut(idx) {
                val dataOff = buf.getInt(stringIdsOff + idx * 4)
                decodeDexMutf8(dexBytes, dataOff)
            }
        }

        fun getTypeName(typeIdx: Int): String {
            if (typeIdx !in 0 until typeIdsSize) return ""
            val strIdx = buf.getInt(typeIdsOff + typeIdx * 4)
            return formatDexDescriptor(getString(strIdx))
        }

        // 1. Scan class_defs for FOD/UDFPS/Biometric/HBM classes
        val relevantTypeIndices = HashSet<Int>()
        if (classDefsSize > 0 && classDefsOff > 0 && classDefsOff + classDefsSize * 32 <= dexBytes.size) {
            for (i in 0 until classDefsSize) {
                val cOff = classDefsOff + i * 32
                val classTypeIdx = buf.getInt(cOff)
                val className = getTypeName(classTypeIdx)
                if (fodDexMethodOrClassRegex.containsMatchIn(className)) {
                    relevantTypeIndices += classTypeIdx
                    val superIdx = buf.getInt(cOff + 8)
                    val superName = if (superIdx != -1) getTypeName(superIdx) else ""
                    val ifacesOff = buf.getInt(cOff + 12)
                    val ifaces = readDexTypeList(dexBytes, buf, ifacesOff, ::getTypeName)

                    val header = buildString {
                        append("class ").append(className)
                        if (superName.isNotBlank() && superName != "java.lang.Object") {
                            append(" : ").append(superName)
                        }
                        if (ifaces.isNotEmpty()) {
                            append(if (superName.isNotBlank() && superName != "java.lang.Object") ", " else " : ")
                            append(ifaces.joinToString(", "))
                        }
                    }
                    matchedClasses += className
                    classHeaders[className] = header
                }
            }
        }

        // 2. Scan method_ids referencing FOD classes OR FOD-specific method names
        if (methodIdsSize > 0 && methodIdsOff > 0 && methodIdsOff + methodIdsSize * 8 <= dexBytes.size) {
            for (i in 0 until methodIdsSize) {
                val mOff = methodIdsOff + i * 8
                val classIdx = buf.getShort(mOff).toInt() and 0xFFFF
                val protoIdx = buf.getShort(mOff + 2).toInt() and 0xFFFF
                val nameIdx = buf.getInt(mOff + 4)

                val methodName = getString(nameIdx)
                val inMatchedClass = classIdx in relevantTypeIndices
                val isInterestingMethodName = fodDexMethodOrClassRegex.containsMatchIn(methodName)
                if (!inMatchedClass && !isInterestingMethodName) continue

                val ownerClass = getTypeName(classIdx)
                if (!inMatchedClass && !fodDexMethodOrClassRegex.containsMatchIn(ownerClass) && methodName.length < 4) continue

                val sig = buildMethodSignature(
                    dexBytes = dexBytes,
                    buf = buf,
                    protoIdsOff = protoIdsOff,
                    protoIdsSize = protoIdsSize,
                    protoIdx = protoIdx,
                    methodName = methodName,
                    getTypeName = ::getTypeName
                )
                val fqMethod = "$ownerClass.$sig"
                if (matchedMethods.size < 160) matchedMethods += fqMethod
                if (inMatchedClass) {
                    classBodyOutlines.getOrPut(ownerClass) { mutableListOf() }.add(sig)
                }
            }
        }

        // 3. Scan FOD/sysfs/prop/Binder/HIDL strings across string pool
        for (idx in 0 until stringIdsSize) {
            val s = getString(idx)
            if (s.length !in 4..180) continue
            val isSysfsOrDev = s.startsWith("/sys/") || s.startsWith("/dev/") || s.startsWith("/vendor/")
            val isProp = s.startsWith("persist.sys.phh") || s.startsWith("persist.sys.fod") ||
                s.startsWith("ro.vendor.fingerprint") || s.startsWith("ro.hardware.fp")
            val isHalDescriptor = (s.contains("hardware.biometrics.fingerprint") ||
                s.contains("vendor.xiaomi.hardware") ||
                s.contains("vendor.oplus.hardware") ||
                s.contains("vendor.goodix.hardware")) && !s.startsWith("L")
            val isKeyHook = s.contains("disp_param", true) || s.contains("fod_status", true) ||
                s.contains("extCmd", false) || s.contains("udfps_hbm", true)

            if (isSysfsOrDev || isProp || isHalDescriptor || isKeyHook) {
                matchedStrings += s
                if (matchedStrings.size >= 100) break
            }
        }
    }

    private fun readDexTypeList(
        dexBytes: ByteArray,
        buf: ByteBuffer,
        offset: Int,
        getTypeName: (Int) -> String
    ): List<String> {
        if (offset <= 0 || offset + 4 > dexBytes.size) return emptyList()
        val size = buf.getInt(offset)
        if (size !in 1..64 || offset + 4 + size * 2 > dexBytes.size) return emptyList()
        return (0 until size).mapNotNull { i ->
            val tIdx = buf.getShort(offset + 4 + i * 2).toInt() and 0xFFFF
            getTypeName(tIdx).takeIf { it.isNotBlank() }
        }
    }

    private fun buildMethodSignature(
        dexBytes: ByteArray,
        buf: ByteBuffer,
        protoIdsOff: Int,
        protoIdsSize: Int,
        protoIdx: Int,
        methodName: String,
        getTypeName: (Int) -> String
    ): String {
        if (protoIdx !in 0 until protoIdsSize || protoIdsOff <= 0 || protoIdsOff + protoIdx * 12 + 12 > dexBytes.size) {
            return "fun $methodName()"
        }
        val pOff = protoIdsOff + protoIdx * 12
        val returnTypeIdx = buf.getInt(pOff + 4)
        val paramsOff = buf.getInt(pOff + 8)
        val retType = getTypeName(returnTypeIdx).substringAfterLast('.')
        val params = readDexTypeList(dexBytes, buf, paramsOff, getTypeName)
            .map { it.substringAfterLast('.') }
        return "fun $methodName(${params.joinToString(", ")}): $retType"
    }

    private fun decodeDexMutf8(bytes: ByteArray, dataOff: Int): String {
        if (dataOff !in 112 until bytes.size) return ""
        var p = dataOff
        // Skip ULEB128 utf16_size (max 5 bytes)
        var shift = 0
        while (p < bytes.size && shift < 35) {
            val b = bytes[p++].toInt() and 0xFF
            if ((b and 0x80) == 0) break
            shift += 7
        }
        val start = p
        while (p < bytes.size && bytes[p] != 0.toByte() && (p - start) < 512) {
            p++
        }
        val len = p - start
        if (len <= 0 || start + len > bytes.size) return ""
        return String(bytes, start, len, Charsets.UTF_8)
    }

    internal fun formatDexDescriptor(desc: String): String {
        if (desc.isEmpty()) return ""
        return when {
            desc.startsWith("L") && desc.endsWith(";") ->
                desc.substring(1, desc.length - 1).replace('/', '.')
            desc.startsWith("[") -> formatDexDescriptor(desc.substring(1)) + "[]"
            desc == "V" -> "void"
            desc == "Z" -> "boolean"
            desc == "B" -> "byte"
            desc == "S" -> "short"
            desc == "C" -> "char"
            desc == "I" -> "int"
            desc == "J" -> "long"
            desc == "F" -> "float"
            desc == "D" -> "double"
            else -> desc
        }
    }
}
