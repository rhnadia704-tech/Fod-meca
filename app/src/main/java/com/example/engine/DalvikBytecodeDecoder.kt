package com.example.engine

import com.example.model.DexMethodTrace
import java.nio.ByteBuffer
import java.nio.ByteOrder

object DalvikBytecodeDecoder {

    private val fodClassOrMethodRegex = Regex(
        "(udfps|fod|fingerprint|biometric|hbm|lhbm|authcontroller|doze|displaymode|brightness|extcmd|disp_param|goodix|xiaomi|oplus|phh|treble|onfingerdown|onfingerup|onacquired|onenroll|illumination|illuminator|touchfeature|displayfeature)",
        RegexOption.IGNORE_CASE
    )

    private val fodBytecodeStringRegex = Regex(
        "(/sys/|/dev/|/vendor/|disp_param|fod_status|fod_ui|extcmd|udfps|lhbm|hbm|biometric|fingerprint|persist\\.sys\\.|ro\\.hardware\\.fp|ro\\.vendor\\.fingerprint)",
        RegexOption.IGNORE_CASE
    )

    fun extractStandardDexSlicesFromVdexOrOat(bytes: ByteArray, maxSlices: Int = 24): List<ByteArray> {
        if (bytes.size < 120) return emptyList()
        val slices = mutableListOf<ByteArray>()
        var pos = 0
        val limit = bytes.size - 112
        while (pos <= limit && slices.size < maxSlices) {
            if (bytes[pos] == 'd'.code.toByte() &&
                bytes[pos + 1] == 'e'.code.toByte() &&
                bytes[pos + 2] == 'x'.code.toByte() &&
                bytes[pos + 3] == '\n'.code.toByte() &&
                bytes[pos + 4] == '0'.code.toByte() &&
                (bytes[pos + 5] == '3'.code.toByte() || bytes[pos + 5] == '4'.code.toByte()) &&
                bytes[pos + 7] == 0.toByte()
            ) {
                val buf = ByteBuffer.wrap(bytes, pos, minOf(112, bytes.size - pos))
                    .slice()
                    .order(ByteOrder.LITTLE_ENDIAN)
                val fileSize = buf.getInt(32)
                val headerSize = buf.getInt(36)
                val endianTag = buf.getInt(40)
                if (headerSize == 112 &&
                    endianTag == 0x12345678 &&
                    fileSize in 112..(bytes.size - pos)
                ) {
                    slices += bytes.copyOfRange(pos, pos + fileSize)
                    pos += ((fileSize + 3) and 3.inv())
                    continue
                }
            }
            pos += 4
        }
        return slices
    }

    fun parseSingleDexWithBytecode(
        dexBytes: ByteArray,
        arscIdMap: Map<Int, ArscEntryRecord> = emptyMap(),
        matchedClasses: MutableSet<String> = linkedSetOf(),
        matchedMethods: MutableSet<String> = linkedSetOf(),
        matchedStrings: MutableSet<String> = linkedSetOf(),
        classHeaders: MutableMap<String, String> = linkedMapOf(),
        classBodyOutlines: MutableMap<String, MutableList<String>> = linkedMapOf(),
        methodTraces: MutableList<DexMethodTrace> = mutableListOf(),
        referencedResIds: MutableSet<Int> = linkedSetOf(),
        resolvedResourceKeys: MutableSet<String> = linkedSetOf()
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

        if (stringIdsSize !in 1..300_000 || stringIdsOff < 112 || stringIdsOff + stringIdsSize * 4 > dexBytes.size) return
        if (typeIdsSize !in 0..120_000 || typeIdsOff + typeIdsSize * 4 > dexBytes.size) return

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

        fun resolveFqMethod(methodIdx: Int): String {
            if (methodIdx !in 0 until methodIdsSize || methodIdsOff <= 0 || methodIdsOff + methodIdx * 8 + 8 > dexBytes.size) {
                return "method@$methodIdx"
            }
            val mOff = methodIdsOff + methodIdx * 8
            val cIdx = buf.getShort(mOff).toInt() and 0xFFFF
            val pIdx = buf.getShort(mOff + 2).toInt() and 0xFFFF
            val nIdx = buf.getInt(mOff + 4)
            val owner = getTypeName(cIdx)
            val name = getString(nIdx)
            val sig = buildMethodSignature(dexBytes, buf, protoIdsOff, protoIdsSize, pIdx, name, ::getTypeName)
            return "$owner.$sig"
        }

        // 1. Scan class_defs & parse class_data_item bytecode for FOD/UDFPS/Biometric/HBM classes
        val relevantTypeIndices = HashSet<Int>()
        if (classDefsSize > 0 && classDefsOff > 0 && classDefsOff + classDefsSize * 32 <= dexBytes.size) {
            for (i in 0 until classDefsSize) {
                val cOff = classDefsOff + i * 32
                val classTypeIdx = buf.getInt(cOff)
                val className = getTypeName(classTypeIdx)
                val isFodClass = fodClassOrMethodRegex.containsMatchIn(className)

                if (isFodClass) {
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

                // Decode Dalvik code_items if class itself matches FOD OR has FOD-named methods
                val classDataOff = buf.getInt(cOff + 24)
                if (classDataOff in 112 until dexBytes.size) {
                    parseClassDataBytecode(
                        dexBytes = dexBytes,
                        buf = buf,
                        classDataOff = classDataOff,
                        isFodClass = isFodClass,
                        arscIdMap = arscIdMap,
                        resolveFqMethod = ::resolveFqMethod,
                        getMethodNameOnly = { mIdx ->
                            if (mIdx in 0 until methodIdsSize && methodIdsOff + mIdx * 8 + 8 <= dexBytes.size) {
                                getString(buf.getInt(methodIdsOff + mIdx * 8 + 4))
                            } else ""
                        },
                        getString = ::getString,
                        methodTraces = methodTraces,
                        referencedResIds = referencedResIds,
                        resolvedResourceKeys = resolvedResourceKeys,
                        matchedStrings = matchedStrings
                    )
                }
            }
        }

        // 2. Scan method_ids for signatures & class outline
        if (methodIdsSize > 0 && methodIdsOff > 0 && methodIdsOff + methodIdsSize * 8 <= dexBytes.size) {
            for (i in 0 until methodIdsSize) {
                val mOff = methodIdsOff + i * 8
                val classIdx = buf.getShort(mOff).toInt() and 0xFFFF
                val protoIdx = buf.getShort(mOff + 2).toInt() and 0xFFFF
                val nameIdx = buf.getInt(mOff + 4)

                val methodName = getString(nameIdx)
                val inMatchedClass = classIdx in relevantTypeIndices
                val isInterestingMethodName = fodClassOrMethodRegex.containsMatchIn(methodName)
                if (!inMatchedClass && !isInterestingMethodName) continue

                val ownerClass = getTypeName(classIdx)
                if (!inMatchedClass && !fodClassOrMethodRegex.containsMatchIn(ownerClass) && methodName.length < 4) continue

                val sig = buildMethodSignature(dexBytes, buf, protoIdsOff, protoIdsSize, protoIdx, methodName, ::getTypeName)
                val fqMethod = "$ownerClass.$sig"
                if (matchedMethods.size < 180) matchedMethods += fqMethod
                if (inMatchedClass) {
                    classBodyOutlines.getOrPut(ownerClass) { mutableListOf() }.add(sig)
                }
            }
        }

        // 3. Scan FOD/sysfs/prop/Binder/HIDL strings across string pool
        for (idx in 0 until stringIdsSize) {
            val s = getString(idx)
            if (s.length !in 4..180) continue
            if (fodBytecodeStringRegex.containsMatchIn(s) && !s.startsWith("L")) {
                matchedStrings += s
                if (matchedStrings.size >= 120) break
            }
        }
    }

    private fun parseClassDataBytecode(
        dexBytes: ByteArray,
        buf: ByteBuffer,
        classDataOff: Int,
        isFodClass: Boolean,
        arscIdMap: Map<Int, ArscEntryRecord>,
        resolveFqMethod: (Int) -> String,
        getMethodNameOnly: (Int) -> String,
        getString: (Int) -> String,
        methodTraces: MutableList<DexMethodTrace>,
        referencedResIds: MutableSet<Int>,
        resolvedResourceKeys: MutableSet<String>,
        matchedStrings: MutableSet<String>
    ) {
        if (methodTraces.size >= 90) return
        val cursor = IntArray(1) { classDataOff }

        val staticFields = readUleb128(dexBytes, cursor).coerceIn(0, 4096)
        val instanceFields = readUleb128(dexBytes, cursor).coerceIn(0, 4096)
        val directMethods = readUleb128(dexBytes, cursor).coerceIn(0, 4096)
        val virtualMethods = readUleb128(dexBytes, cursor).coerceIn(0, 4096)

        repeat(staticFields + instanceFields) {
            readUleb128(dexBytes, cursor) // field_idx_diff
            readUleb128(dexBytes, cursor) // access_flags
        }

        fun readMethodList(count: Int) {
            var methodIdx = 0
            for (m in 0 until count) {
                if (cursor[0] >= dexBytes.size || methodTraces.size >= 90) break
                val diff = readUleb128(dexBytes, cursor)
                readUleb128(dexBytes, cursor) // access_flags
                val codeOff = readUleb128(dexBytes, cursor)
                methodIdx += diff
                if (codeOff <= 0 || codeOff + 16 > dexBytes.size) continue

                val methodName = getMethodNameOnly(methodIdx)
                val shouldInspect = isFodClass || fodClassOrMethodRegex.containsMatchIn(methodName)
                if (!shouldInspect) continue

                val trace = decodeCodeItem(
                    dexBytes = dexBytes,
                    buf = buf,
                    codeOff = codeOff,
                    fqMethod = resolveFqMethod(methodIdx),
                    arscIdMap = arscIdMap,
                    resolveFqMethod = resolveFqMethod,
                    getString = getString
                )
                if (trace != null && (trace.invokedMethods.isNotEmpty() || trace.referencedResIds.isNotEmpty() || trace.referencedStrings.isNotEmpty())) {
                    methodTraces += trace
                    referencedResIds.addAll(trace.referencedResIds)
                    resolvedResourceKeys.addAll(trace.resolvedResKeys)
                    matchedStrings.addAll(trace.referencedStrings)
                }
            }
        }

        readMethodList(directMethods)
        readMethodList(virtualMethods)
    }

    internal fun decodeCodeItem(
        dexBytes: ByteArray,
        buf: ByteBuffer,
        codeOff: Int,
        fqMethod: String,
        arscIdMap: Map<Int, ArscEntryRecord>,
        resolveFqMethod: (Int) -> String,
        getString: (Int) -> String
    ): DexMethodTrace? {
        if (codeOff + 16 > dexBytes.size) return null
        val insnsSize = buf.getInt(codeOff + 12)
        val insnsStart = codeOff + 16
        if (insnsSize <= 0 || insnsSize > 16_384 || insnsStart + insnsSize * 2 > dexBytes.size) return null

        val invoked = linkedSetOf<String>()
        val resIds = linkedSetOf<Int>()
        val resKeys = linkedSetOf<String>()
        val strRefs = linkedSetOf<String>()

        fun u16(unitIdx: Int): Int {
            val byteOff = insnsStart + unitIdx * 2
            if (byteOff + 2 > dexBytes.size) return 0
            return buf.getShort(byteOff).toInt() and 0xFFFF
        }

        fun s32(unitIdx: Int): Int {
            val byteOff = insnsStart + unitIdx * 2
            if (byteOff + 4 > dexBytes.size) return 0
            return buf.getInt(byteOff)
        }

        var pc = 0
        while (pc < insnsSize) {
            val unit0 = u16(pc)
            val opcode = unit0 and 0xFF
            // Handle pseudo-opcode data payloads embedded in instruction stream
            if (unit0 == 0x0100) { // packed-switch-payload
                val size = u16(pc + 1)
                pc += 4 + size * 2
                continue
            } else if (unit0 == 0x0200) { // sparse-switch-payload
                val size = u16(pc + 1)
                pc += 2 + size * 4
                continue
            } else if (unit0 == 0x0300) { // fill-array-data-payload
                val elemWidth = u16(pc + 1)
                val size = s32(pc + 2)
                val dataUnits = ((size.toLong() * elemWidth.toLong()) + 1L) / 2L
                pc += 4 + dataUnits.coerceIn(0L, 8192L).toInt()
                continue
            }

            when (opcode) {
                0x14 -> { // const vAA, #+BBBBBBBB (31i)
                    val imm = s32(pc + 1)
                    val pkgByte = (imm ushr 24) and 0xFF
                    if (pkgByte == 0x7F || pkgByte == 0x01) {
                        resIds += imm
                        val entry = arscIdMap[imm]
                        if (entry != null) {
                            val prefix = if (entry.packageName.isNotBlank()) "${entry.packageName}:" else ""
                            resKeys += "$prefix${entry.typeName}/${entry.keyName}"
                        } else {
                            resKeys += "0x${imm.toUInt().toString(16)}"
                        }
                    }
                }
                0x1a -> { // const-string vAA, string@BBBB (21c)
                    val strIdx = u16(pc + 1)
                    val s = getString(strIdx)
                    if (s.length in 3..180 && fodBytecodeStringRegex.containsMatchIn(s)) {
                        strRefs += s
                    }
                }
                0x1b -> { // const-string/jumbo vAA, string@BBBBBBBB (31c)
                    val strIdx = s32(pc + 1)
                    val s = getString(strIdx)
                    if (s.length in 3..180 && fodBytecodeStringRegex.containsMatchIn(s)) {
                        strRefs += s
                    }
                }
                in 0x6e..0x72, // invoke-virtual, super, direct, static, interface (35c)
                in 0x74..0x78 -> { // invoke-*/range (3rc)
                    val methodIdx = u16(pc + 1)
                    val called = resolveFqMethod(methodIdx)
                    if (!called.startsWith("java.lang.Object.") &&
                        !called.startsWith("java.lang.StringBuilder.") &&
                        !called.startsWith("android.util.Log.")
                    ) {
                        invoked += called
                    }
                }
            }
            pc += dalvikWidthUnits(opcode)
        }

        val snippet = buildString {
            appendLine(fqMethod)
            resKeys.take(10).forEach { k -> appendLine("  res: $k") }
            strRefs.take(8).forEach { s -> appendLine("  str: \"$s\"") }
            invoked.filter {
                fodClassOrMethodRegex.containsMatchIn(it) ||
                    it.contains("Resources.get", true) ||
                    it.contains("SurfaceControl", true) ||
                    it.contains("DisplayManager", true) ||
                    it.contains("IBinder", true) ||
                    it.contains("biometrics", true) ||
                    it.contains("File", true)
            }.take(14).forEach { c -> appendLine("  call -> $c") }
        }.trim()

        return DexMethodTrace(
            fqMethod = fqMethod,
            invokedMethods = invoked.take(24),
            referencedResIds = resIds.take(20),
            resolvedResKeys = resKeys.take(20),
            referencedStrings = strRefs.take(16),
            bytecodeSnippet = snippet
        )
    }

    private fun dalvikWidthUnits(opcode: Int): Int = when (opcode) {
        0x00, 0x01, 0x04, 0x07, in 0x0a..0x12, in 0x1d..0x1e, 0x21, 0x27,
        in 0x28..0x28, in 0x3e..0x43, in 0x73..0x73, in 0x79..0x7a,
        in 0x7b..0x8f, in 0xb0..0xcf -> 1

        0x02, 0x05, 0x08, 0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c, 0x1f, 0x20,
        0x22, 0x23, 0x29, in 0x2d..0x3d, in 0x44..0x6d, in 0xd0..0xe2 -> 2

        0x03, 0x06, 0x09, 0x14, 0x17, 0x1b, 0x24, 0x25, 0x26,
        in 0x2a..0x2c, in 0x6e..0x72, in 0x74..0x78, in 0xfa..0xfd -> 3

        0xf8, 0xf9 -> 4 // invoke-polymorphic / range (45cc/4rcc) -> conservative 4 units; 0x18 is 5 units
        0x18 -> 5 // const-wide
        0xfe, 0xff -> 2
        else -> 1
    }

    private fun readUleb128(bytes: ByteArray, cursor: IntArray): Int {
        var result = 0
        var shift = 0
        var pos = cursor[0]
        for (i in 0 until 5) {
            if (pos >= bytes.size) break
            val b = bytes[pos++].toInt() and 0xFF
            result = result or ((b and 0x7F) shl shift)
            if ((b and 0x80) == 0) break
            shift += 7
        }
        cursor[0] = pos
        return result
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
