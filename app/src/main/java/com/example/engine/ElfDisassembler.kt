package com.example.engine

import com.example.model.ElfBinaryAnalysis
import java.nio.ByteBuffer
import java.nio.ByteOrder

object ElfDisassembler {

    private val fodKeywords = listOf(
        "fod", "udfps", "hbm", "lhbm", "finger", "biometric", "enroll", "auth",
        "goodix", "fpc", "silead", "focal", "egis", "synaptics", "optical",
        "ultrasonic", "dim", "backlight", "brightness", "drm", "panel", "touch",
        "zorder", "alpha", "display", "notify", "ioctl", "/sys/", "/dev/"
    )

    fun analyzeBinary(path: String, bytes: ByteArray?, accessError: String?): ElfBinaryAnalysis {
        if (bytes == null || bytes.size < 64) {
            return ElfBinaryAnalysis(
                path = path,
                architecture = "UNKNOWN",
                fileSizeBytes = bytes?.size?.toLong() ?: 0L,
                isReadable = false,
                accessError = accessError ?: "Unreadable or truncated file"
            )
        }

        if (bytes[0] != 0x7F.toByte() || bytes[1] != 'E'.code.toByte() ||
            bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) {
            return ElfBinaryAnalysis(
                path = path,
                architecture = "NOT_ELF",
                fileSizeBytes = bytes.size.toLong(),
                isReadable = true,
                accessError = "File does not contain ELF magic header"
            )
        }

        val elfClass = bytes[4].toInt() and 0xFF // 1 = ELF32, 2 = ELF64
        val dataEnc = bytes[5].toInt() and 0xFF // 1 = LSB, 2 = MSB
        val order = if (dataEnc == 2) ByteOrder.BIG_ENDIAN else ByteOrder.LITTLE_ENDIAN
        val buf = ByteBuffer.wrap(bytes).order(order)

        val eMachine = buf.getShort(18).toInt() and 0xFFFF
        val archName = when (eMachine) {
            183 -> "AArch64 (ARM64)"
            40 -> "ARM (32-bit)"
            62 -> "x86_64"
            3 -> "x86"
            else -> "EM_$eMachine"
        }

        return if (elfClass == 2) {
            parseElf64(path, bytes, buf, archName, eMachine == 183)
        } else {
            parseElf32Basic(path, bytes, archName)
        }
    }

    private data class SectionHeader(
        val nameOffset: Int,
        val type: Int,
        val addr: Long,
        val offset: Long,
        val size: Long,
        val link: Int,
        val entSize: Long,
        var name: String = ""
    )

    private fun parseElf64(
        path: String,
        bytes: ByteArray,
        buf: ByteBuffer,
        archName: String,
        isAarch64: Boolean
    ): ElfBinaryAnalysis {
        val eShoff = buf.getLong(40)
        val eShentsize = buf.getShort(58).toInt() and 0xFFFF
        val eShnum = buf.getShort(60).toInt() and 0xFFFF
        val eShstrndx = buf.getShort(62).toInt() and 0xFFFF

        val sections = mutableListOf<SectionHeader>()
        if (eShoff > 0 && eShentsize >= 64 && eShnum in 1..4096) {
            for (i in 0 until eShnum) {
                val off = (eShoff + i.toLong() * eShentsize).toInt()
                if (off < 0 || off + 64 > bytes.size) break
                sections += SectionHeader(
                    nameOffset = buf.getInt(off),
                    type = buf.getInt(off + 4),
                    addr = buf.getLong(off + 16),
                    offset = buf.getLong(off + 24),
                    size = buf.getLong(off + 32),
                    link = buf.getInt(off + 40),
                    entSize = buf.getLong(off + 56)
                )
            }
        }

        val shstr = sections.getOrNull(eShstrndx)
        if (shstr != null && shstr.offset >= 0 && shstr.offset + shstr.size <= bytes.size) {
            sections.forEach { s ->
                s.name = readCString(bytes, (shstr.offset + s.nameOffset).toInt())
            }
        }

        val dynstr = sections.firstOrNull { it.name == ".dynstr" }
        val dynamic = sections.firstOrNull { it.name == ".dynamic" || it.type == 6 }
        val dynsym = sections.firstOrNull { it.name == ".dynsym" || it.type == 11 }
        val textSec = sections.firstOrNull { it.name == ".text" }

        val dtNeeded = mutableListOf<String>()
        if (dynamic != null && dynstr != null && dynamic.offset >= 0 &&
            dynamic.offset + dynamic.size <= bytes.size
        ) {
            var pos = dynamic.offset.toInt()
            val end = (dynamic.offset + dynamic.size).toInt()
            while (pos + 16 <= end) {
                val tag = buf.getLong(pos)
                val value = buf.getLong(pos + 8)
                if (tag == 0L) break // DT_NULL
                if (tag == 1L) { // DT_NEEDED
                    val strPos = (dynstr.offset + value).toInt()
                    val lib = readCString(bytes, strPos)
                    if (lib.isNotBlank()) dtNeeded += lib
                }
                pos += 16
            }
        }

        data class SymEntry(val name: String, val value: Long, val size: Long)
        val matchedSymbols = mutableListOf<SymEntry>()
        if (dynsym != null && dynstr != null && dynsym.offset >= 0 &&
            dynsym.offset + dynsym.size <= bytes.size
        ) {
            val step = maxOf(dynsym.entSize.toInt(), 24)
            var pos = dynsym.offset.toInt()
            val end = (dynsym.offset + dynsym.size).toInt()
            while (pos + 24 <= end) {
                val stName = buf.getInt(pos)
                val stValue = buf.getLong(pos + 8)
                val stSize = buf.getLong(pos + 16)
                val name = readCString(bytes, (dynstr.offset + stName).toInt())
                if (name.isNotBlank() && matchesFodKeyword(name)) {
                    matchedSymbols += SymEntry(name, stValue, stSize)
                }
                pos += step
            }
        }

        val strings = extractRelevantStrings(bytes, limit = 240)
            .sortedWith(
                compareByDescending<String> {
                    it.startsWith("/sys/") || it.startsWith("/dev/") ||
                        it.contains("extcmd", true) || it.contains("disp_param", true) ||
                        it.contains("onfinger", true) || it.contains("hbm", true) || it.contains("lhbm", true)
                }.thenByDescending { it.contains("udfps", true) || it.contains("fod", true) }
            )

        val prioritizedSymbols = matchedSymbols.sortedByDescending { sym ->
            val l = sym.name.lowercase()
            when {
                l.contains("extcmd") || l.contains("onfinger") || l.contains("hbm") || l.contains("lhbm") -> 3
                l.contains("fod") || l.contains("udfps") || l.contains("enroll") || l.contains("acquire") -> 2
                else -> 1
            }
        }

        val disasmBuilder = StringBuilder()
        if (isAarch64 && textSec != null && textSec.offset >= 0 &&
            textSec.offset + textSec.size <= bytes.size
        ) {
            val targets = prioritizedSymbols.filter {
                it.value >= textSec.addr && it.value < textSec.addr + textSec.size
            }.take(10)

            if (targets.isNotEmpty()) {
                for (sym in targets) {
                    val fileStart = (textSec.offset + (sym.value - textSec.addr)).toInt()
                    val instrCount = minOf(
                        maxOf((sym.size / 4L).toInt(), 24),
                        50
                    )
                    disasmBuilder.appendLine("// Function: ${sym.name} @ 0x${sym.value.toString(16)} (${sym.size}B)")
                    disasmBuilder.appendLine(decodeAarch64Window(bytes, buf, fileStart, sym.value, instrCount))
                }
            } else {
                // Decode entry snippet of .text if symbols were stripped
                val count = minOf((textSec.size / 4L).toInt(), 48)
                disasmBuilder.appendLine("// .text entry snippet (symbols stripped) @ 0x${textSec.addr.toString(16)}")
                disasmBuilder.appendLine(
                    decodeAarch64Window(bytes, buf, textSec.offset.toInt(), textSec.addr, count)
                )
            }
        } else if (sections.isEmpty()) {
            disasmBuilder.appendLine("// Section headers stripped; extracted dynamic strings and ELF header metadata only.")
        }

        return ElfBinaryAnalysis(
            path = path,
            architecture = archName,
            fileSizeBytes = bytes.size.toLong(),
            isReadable = true,
            dtNeeded = dtNeeded.distinct(),
            fodSymbols = prioritizedSymbols.map {
                "${it.name} @0x${it.value.toString(16)} (${it.size}B)"
            }.distinct().take(160),
            fodStrings = strings,
            disassemblyPseudoCode = disasmBuilder.toString().trim()
        )
    }

    private fun parseElf32Basic(path: String, bytes: ByteArray, archName: String): ElfBinaryAnalysis {
        val strings = extractRelevantStrings(bytes, limit = 120)
        return ElfBinaryAnalysis(
            path = path,
            architecture = archName,
            fileSizeBytes = bytes.size.toLong(),
            isReadable = true,
            fodStrings = strings,
            disassemblyPseudoCode = "// ELF32 binary inspected via printable strings and header metadata."
        )
    }

    private fun decodeAarch64Window(
        bytes: ByteArray,
        buf: ByteBuffer,
        fileOffset: Int,
        virtualBase: Long,
        maxInstructions: Int
    ): String {
        val sb = StringBuilder()
        for (i in 0 until maxInstructions) {
            val pos = fileOffset + i * 4
            if (pos < 0 || pos + 4 > bytes.size) break
            val insn = buf.getInt(pos)
            val vaddr = virtualBase + i * 4L
            val decoded = decodeAarch64Instruction(insn, vaddr)
            sb.appendLine("  0x${vaddr.toString(16).padStart(6, '0')}: ${insn.toUInt().toString(16).padStart(8, '0')}  $decoded")
        }
        return sb.toString()
    }

    private fun decodeAarch64Instruction(insn: Int, vaddr: Long): String {
        val op = insn ushr 26
        return when {
            insn == 0xD65F03C0.toInt() -> "RET                  // return from subroutine"
            insn == 0xD503201F.toInt() -> "NOP"
            (insn and 0xFC000000.toInt()) == 0x94000000.toInt() -> {
                val imm26 = signExtend(insn and 0x03FFFFFF, 26) shl 2
                val target = vaddr + imm26
                "BL   0x${target.toString(16)}        // call sub_0x${target.toString(16)}()"
            }
            (insn and 0xFC000000.toInt()) == 0x14000000 -> {
                val imm26 = signExtend(insn and 0x03FFFFFF, 26) shl 2
                val target = vaddr + imm26
                "B    0x${target.toString(16)}        // goto 0x${target.toString(16)}"
            }
            (insn and 0xFFE0001F.toInt()) == 0xD4000001.toInt() -> {
                val svcImm = (insn ushr 5) and 0xFFFF
                "SVC  #0x${svcImm.toString(16)}          // syscall()"
            }
            (insn and 0x9F000000.toInt()) == 0x90000000.toInt() -> {
                val rd = insn and 0x1F
                val immlo = (insn ushr 29) and 0x3
                val immhi = (insn ushr 5) and 0x7FFFF
                val imm = signExtend((immhi shl 2) or immlo, 21).toLong() shl 12
                val page = (vaddr and -4096L) + imm
                "ADRP X$rd, 0x${page.toString(16)}   // X$rd = page(0x${page.toString(16)})"
            }
            (insn and 0x7F800000) == 0x52800000 -> {
                val sf = (insn ushr 31) and 1
                val rd = insn and 0x1F
                val imm16 = (insn ushr 5) and 0xFFFF
                val reg = if (sf == 1) "X$rd" else "W$rd"
                "MOVZ $reg, #0x${imm16.toString(16)}   // $reg = $imm16"
            }
            (insn and 0x7F000000) == 0x34000000 -> {
                val isCbnz = ((insn ushr 24) and 1) == 1
                val rt = insn and 0x1F
                val imm19 = signExtend((insn ushr 5) and 0x7FFFF, 19) shl 2
                val target = vaddr + imm19
                val mnem = if (isCbnz) "CBNZ" else "CBZ "
                val cond = if (isCbnz) "!= 0" else "== 0"
                "$mnem X$rt, 0x${target.toString(16)}  // if (X$rt $cond) goto 0x${target.toString(16)}"
            }
            (insn and 0x7F800000) == 0x11000000 -> {
                val sf = (insn ushr 31) and 1
                val rd = insn and 0x1F
                val rn = (insn ushr 5) and 0x1F
                val imm12 = (insn ushr 10) and 0xFFF
                val p = if (sf == 1) "X" else "W"
                "ADD  $p$rd, $p$rn, #0x${imm12.toString(16)}"
            }
            (insn and 0xBFC00000.toInt()) == 0xB9400000.toInt() -> {
                val rt = insn and 0x1F
                val rn = (insn ushr 5) and 0x1F
                val imm12 = ((insn ushr 10) and 0xFFF) * 8
                "LDR  X$rt, [X$rn, #0x${imm12.toString(16)}] // X$rt = *(X$rn + 0x${imm12.toString(16)})"
            }
            (insn and 0xBFC00000.toInt()) == 0xB9000000.toInt() -> {
                val rt = insn and 0x1F
                val rn = (insn ushr 5) and 0x1F
                val imm12 = ((insn ushr 10) and 0xFFF) * 8
                "STR  X$rt, [X$rn, #0x${imm12.toString(16)}] // *(X$rn + 0x${imm12.toString(16)}) = X$rt"
            }
            else -> "INSN_OP_$op (0x${insn.toUInt().toString(16)})"
        }
    }

    private fun signExtend(value: Int, bits: Int): Int {
        val shift = 32 - bits
        return (value shl shift) shr shift
    }

    private fun readCString(bytes: ByteArray, offset: Int): String {
        if (offset < 0 || offset >= bytes.size) return ""
        val sb = StringBuilder()
        var idx = offset
        while (idx < bytes.size && sb.length < 256) {
            val b = bytes[idx].toInt() and 0xFF
            if (b == 0) break
            if (b in 32..126) sb.append(b.toChar()) else return ""
            idx++
        }
        return sb.toString()
    }

    private fun extractRelevantStrings(bytes: ByteArray, limit: Int): List<String> {
        val found = LinkedHashSet<String>()
        val cur = StringBuilder()
        for (b in bytes) {
            val c = b.toInt() and 0xFF
            if (c in 32..126) {
                cur.append(c.toChar())
            } else {
                if (cur.length >= 5) {
                    val str = cur.toString()
                    if (matchesFodKeyword(str)) {
                        found += str.take(180)
                        if (found.size >= limit) break
                    }
                }
                cur.setLength(0)
            }
        }
        return found.toList()
    }

    private fun matchesFodKeyword(text: String): Boolean {
        val lower = text.lowercase()
        return fodKeywords.any { lower.contains(it) }
    }
}
