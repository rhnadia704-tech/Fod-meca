package com.example.engine

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.concurrent.TimeUnit

data class ShellResult(
    val exitCode: Int,
    val stdout: String,
    val stderr: String,
    val timedOut: Boolean = false,
    val usedRoot: Boolean = false
) {
    val isSuccess: Boolean get() = !timedOut && exitCode == 0
}

data class BinaryReadResult(
    val bytes: ByteArray?,
    val accessError: String?
)

object ShellExecutor {

    private val forbiddenTokens = listOf(
        "mount ", "umount ", "rm ", "mv ", "cp ", "chmod ", "chown ",
        "setprop ", "dd of=", "flash", "fastboot", "mkfs", "insmod", "rmmod",
        " > ", " >> ", "tee ", "echo "
    )

    private fun validateReadOnly(command: String) {
        val lower = command.lowercase()
        for (token in forbiddenTokens) {
            if (lower.contains(token)) {
                throw SecurityException("Non-intrusive read-only policy blocked command containing '$token'")
            }
        }
    }

    suspend fun exec(
        command: String,
        useRoot: Boolean = false,
        timeoutMs: Long = 10_000L,
        maxOutputBytes: Int = 4 * 1024 * 1024
    ): ShellResult = withContext(Dispatchers.IO) {
        validateReadOnly(command)
        val args = if (useRoot) {
            listOf("su", "-c", command)
        } else {
            listOf("sh", "-c", command)
        }
        try {
            val process = ProcessBuilder(args)
                .redirectErrorStream(false)
                .start()

            val result = withTimeoutOrNull(timeoutMs) {
                val stdoutBytes = ByteArrayOutputStream()
                val stderrBytes = ByteArrayOutputStream()

                val outReader = Thread {
                    val buf = ByteArray(8192)
                    var total = 0
                    process.inputStream.use { input ->
                        while (true) {
                            val read = input.read(buf)
                            if (read <= 0) break
                            val toWrite = minOf(read, maxOutputBytes - total)
                            if (toWrite > 0) {
                                stdoutBytes.write(buf, 0, toWrite)
                                total += toWrite
                            }
                            if (total >= maxOutputBytes) break
                        }
                    }
                }
                val errReader = Thread {
                    val buf = ByteArray(4096)
                    var total = 0
                    process.errorStream.use { input ->
                        while (true) {
                            val read = input.read(buf)
                            if (read <= 0) break
                            val toWrite = minOf(read, 512 * 1024 - total)
                            if (toWrite > 0) {
                                stderrBytes.write(buf, 0, toWrite)
                                total += toWrite
                            }
                            if (total >= 512 * 1024) break
                        }
                    }
                }
                outReader.start()
                errReader.start()
                val exit = process.waitFor()
                outReader.join(1500)
                errReader.join(1500)
                ShellResult(
                    exitCode = exit,
                    stdout = stdoutBytes.toString(Charsets.UTF_8.name()),
                    stderr = stderrBytes.toString(Charsets.UTF_8.name()),
                    timedOut = false,
                    usedRoot = useRoot
                )
            }
            if (result == null) {
                process.destroyForcibly()
                process.waitFor(500, TimeUnit.MILLISECONDS)
                ShellResult(
                    exitCode = -1,
                    stdout = "",
                    stderr = "Command timed out after ${timeoutMs}ms: $command",
                    timedOut = true,
                    usedRoot = useRoot
                )
            } else {
                result
            }
        } catch (e: Exception) {
            ShellResult(
                exitCode = -1,
                stdout = "",
                stderr = e.message ?: "Execution failed",
                timedOut = false,
                usedRoot = useRoot
            )
        }
    }

    suspend fun testRootAccess(): Pair<Boolean, String> {
        val res = exec("id", useRoot = true, timeoutMs = 5_000L)
        val granted = res.isSuccess && res.stdout.contains("uid=0")
        val detail = when {
            granted -> res.stdout.trim()
            res.stderr.isNotBlank() -> res.stderr.trim()
            else -> "exit=${res.exitCode}"
        }
        return granted to detail
    }

    suspend fun readBinaryFile(
        path: String,
        useRoot: Boolean,
        maxBytes: Int = 8 * 1024 * 1024
    ): BinaryReadResult = withContext(Dispatchers.IO) {
        val file = File(path)
        if (file.exists() && file.canRead()) {
            return@withContext try {
                val len = minOf(file.length(), maxBytes.toLong()).toInt()
                val buf = ByteArray(len)
                file.inputStream().use { input ->
                    var offset = 0
                    while (offset < len) {
                        val r = input.read(buf, offset, len - offset)
                        if (r <= 0) break
                        offset += r
                    }
                    if (offset == len) buf else buf.copyOf(offset)
                }.let { BinaryReadResult(it, null) }
            } catch (e: Exception) {
                BinaryReadResult(null, e.message ?: "Direct read failed")
            }
        }

        if (!useRoot) {
            return@withContext BinaryReadResult(
                null,
                "Access denied or non-readable without root: $path"
            )
        }

        val safePath = path.replace("'", "'\\''")
        val args = listOf("su", "-c", "head -c $maxBytes '$safePath'")
        try {
            val process = ProcessBuilder(args).start()
            val out = ByteArrayOutputStream()
            val err = ByteArrayOutputStream()
            val tOut = Thread { process.inputStream.copyTo(out, 16384) }
            val tErr = Thread { process.errorStream.copyTo(err, 4096) }
            tOut.start()
            tErr.start()
            val finished = process.waitFor(8, TimeUnit.SECONDS)
            if (!finished) {
                process.destroyForcibly()
                return@withContext BinaryReadResult(null, "Timed out reading $path via root")
            }
            tOut.join(1000)
            tErr.join(1000)
            val data = out.toByteArray()
            if (process.exitValue() == 0 && data.isNotEmpty()) {
                BinaryReadResult(data, null)
            } else {
                val errMsg = err.toString(Charsets.UTF_8.name()).trim()
                    .ifBlank { "exit=${process.exitValue()}" }
                BinaryReadResult(null, errMsg)
            }
        } catch (e: Exception) {
            BinaryReadResult(null, e.message ?: "Root binary read failed")
        }
    }
}
