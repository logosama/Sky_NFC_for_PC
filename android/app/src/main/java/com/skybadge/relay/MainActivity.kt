package com.skybadge.relay

import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.NfcA
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.VibrationEffect
import android.os.Vibrator
import android.util.Base64
import android.util.Log
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.textfield.TextInputEditText
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException

/**
 * Sky Badge Relay - reads a Sky badge (NTAG215) with the phone's NFC and
 * forwards the raw dump to the PC, where badge_inject.py parses it and
 * injects the URL into the game.
 */
class MainActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "SkyBadgeRelay"
        private const val PREFS = "skybadge_relay"
        private const val KEY_IP = "pc_ip"
        private const val KEY_PORT = "pc_port"
        private const val KEY_TOKEN = "token"
        private const val DEFAULT_PORT = "8799"
        private const val DEBOUNCE_MS = 3000L
        private const val FAILURE_RETRY_MS = 750L
        private const val TRANSCEIVE_TIMEOUT_MS = 500
        private const val READ_DEADLINE_MS = 10000L
        private const val NTAG_PAGES = 135 // NTAG215: pages 0..134, 4 bytes each
        private const val NTAG_TOTAL = NTAG_PAGES * 4
        private const val BLOCK_PAGES = 4
        private val VIB_SUCCESS = longArrayOf(0, 120)
        private val VIB_ERROR = longArrayOf(0, 80, 120, 80)
    }

    private var nfcAdapter: NfcAdapter? = null
    private var readerModeEnabled = false
    private val executor = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())

    private lateinit var statusText: TextView
    private lateinit var ipEdit: TextInputEditText
    private lateinit var portEdit: TextInputEditText
    private lateinit var tokenEdit: TextInputEditText
    private lateinit var saveButton: Button

    // All three fields are only touched from the main thread.
    private var lastScanAt = 0L
    private var lastAttemptFailed = false
    private var busy = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        statusText = findViewById(R.id.status_text)
        ipEdit = findViewById(R.id.et_ip)
        portEdit = findViewById(R.id.et_port)
        tokenEdit = findViewById(R.id.et_token)
        saveButton = findViewById(R.id.btn_save)

        ipEdit.setText(prefs.getString(KEY_IP, ""))
        portEdit.setText(prefs.getString(KEY_PORT, DEFAULT_PORT))
        tokenEdit.setText(prefs.getString(KEY_TOKEN, ""))

        saveButton.setOnClickListener {
            prefs.edit()
                .putString(KEY_IP, ipEdit.text?.toString()?.trim().orEmpty())
                .putString(KEY_PORT, portEdit.text?.toString()?.trim().orEmpty())
                .putString(KEY_TOKEN, tokenEdit.text?.toString()?.trim().orEmpty())
                .apply()
            saveButton.text = getString(R.string.btn_saved)
            saveButton.postDelayed(
                { saveButton.text = getString(R.string.btn_save) }, 1500,
            )
        }

        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        if (nfcAdapter == null) {
            setStatus(getString(R.string.status_nfc_missing), error = true)
        } else {
            setStatus(getString(R.string.status_ready))
        }
    }

    override fun onResume() {
        super.onResume()
        nfcAdapter?.let { adapter ->
            if (!readerModeEnabled) {
                val flags = NfcAdapter.FLAG_READER_NFC_A or
                    NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK or
                    NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS
                adapter.enableReaderMode(this, ::onTagDiscovered, flags, null)
                readerModeEnabled = true
            }
        }
    }

    override fun onPause() {
        super.onPause()
        if (readerModeEnabled) {
            nfcAdapter?.disableReaderMode(this)
            readerModeEnabled = false
        }
    }

    override fun onDestroy() {
        mainHandler.removeCallbacksAndMessages(null)
        executor.shutdownNow()
        super.onDestroy()
    }

    /** Reader-mode callbacks arrive on a binder thread; all UI work is main-thread. */
    private fun onTagDiscovered(tag: Tag) {
        postUi { handleTagOnMain(tag) }
    }

    private fun postUi(block: () -> Unit) {
        mainHandler.post {
            if (!isFinishing && !isDestroyed) block()
        }
    }

    private fun handleTagOnMain(tag: Tag) {
        val now = System.currentTimeMillis()
        val cooldown = if (lastAttemptFailed) FAILURE_RETRY_MS else DEBOUNCE_MS
        if (busy || now - lastScanAt < cooldown) return
        lastScanAt = now
        lastAttemptFailed = false

        val server = buildServerConfig()
        if (server == null) {
            lastAttemptFailed = true
            lastScanAt = now
            setStatus(getString(R.string.status_error, getString(R.string.error_no_pc_ip)), error = true)
            vibrate(VIB_ERROR)
            return
        }

        busy = true
        val uidHex = tag.id.joinToString("") { "%02x".format(it) }.uppercase()
        setStatus(getString(R.string.status_reading, uidHex))
        try {
            executor.execute { scanAndSend(tag, server, uidHex) }
        } catch (e: RejectedExecutionException) {
            busy = false
            lastAttemptFailed = true
            lastScanAt = System.currentTimeMillis()
            setStatus(getString(R.string.status_error, getString(R.string.error_app_closing)), error = true)
            vibrate(VIB_ERROR)
        } catch (e: Exception) {
            busy = false
            lastAttemptFailed = true
            lastScanAt = System.currentTimeMillis()
            Log.w(TAG, "cannot start scan", e)
            setStatus(getString(R.string.status_error, getString(R.string.error_unexpected)), error = true)
            vibrate(VIB_ERROR)
        }
    }

    private fun scanAndSend(tag: Tag, server: ServerConfig, uidHex: String) {
        var failed = true
        try {
            val dump = readTag(tag) { pages ->
                postUi {
                    if (busy) {
                        setStatus(
                            getString(R.string.status_reading_progress, pages, NTAG_PAGES, uidHex),
                        )
                    }
                }
            }
            if (dump == null) {
                postUi {
                    setStatus(
                        getString(R.string.status_error, getString(R.string.error_read_failed)),
                        error = true,
                    )
                    vibrate(VIB_ERROR)
                }
                return
            }
            postUi { setStatus(getString(R.string.status_sending, uidHex)) }
            val err = postToPc(server, dump)
            if (err == null) {
                failed = false
                postUi {
                    setStatus(getString(R.string.status_sent, uidHex))
                    vibrate(VIB_SUCCESS)
                }
            } else {
                postUi {
                    setStatus(getString(R.string.status_error, err), error = true)
                    vibrate(VIB_ERROR)
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "scan failed", e)
            postUi {
                setStatus(getString(R.string.status_error, getString(R.string.error_unexpected)), error = true)
                vibrate(VIB_ERROR)
            }
        } finally {
            postUi { finishScan(failed) }
        }
    }

    private fun finishScan(failed: Boolean) {
        busy = false
        lastAttemptFailed = failed
        lastScanAt = System.currentTimeMillis()
    }

    private data class ServerConfig(val ip: String, val port: Int, val token: String)

    private fun buildServerConfig(): ServerConfig? {
        val ip = ipEdit.text?.toString()?.trim().orEmpty()
        if (ip.isEmpty()) return null
        val port = portEdit.text?.toString()?.trim()?.toIntOrNull()
            ?: DEFAULT_PORT.toInt()
        val token = tokenEdit.text?.toString()?.trim().orEmpty()
        return ServerConfig(ip, port, token)
    }

    /**
     * Read all NTAG215 pages via NfcA READ (0x30).
     *
     * READ always returns 16 bytes (four pages). Read pages 0..131 in 33
     * four-page commands, then obtain pages 132..134 from the last valid
     * starts (129..131) to avoid addressing page 135. 36 commands total.
     */
    private fun readTag(tag: Tag, onProgress: (Int) -> Unit): ByteArray? {
        val nfcA = NfcA.get(tag) ?: return null
        nfcA.timeout = TRANSCEIVE_TIMEOUT_MS
        val deadline = System.currentTimeMillis() + READ_DEADLINE_MS
        try {
            nfcA.connect()
            val dump = ByteArray(NTAG_TOTAL)
            var page = 0
            while (page + BLOCK_PAGES <= NTAG_PAGES) {
                if (System.currentTimeMillis() > deadline) return null
                val cmd = byteArrayOf(0x30.toByte(), page.toByte())
                val resp = transceiveWithRetry(nfcA, cmd) ?: return null
                if (resp.size < BLOCK_PAGES * 4) return null
                System.arraycopy(resp, 0, dump, page * 4, BLOCK_PAGES * 4)
                page += BLOCK_PAGES
                onProgress(page)
            }
            for (targetPage in (NTAG_PAGES - 3) until NTAG_PAGES) {
                if (System.currentTimeMillis() > deadline) return null
                val startPage = targetPage - 3 // 129, 130, 131
                val cmd = byteArrayOf(0x30.toByte(), startPage.toByte())
                val resp = transceiveWithRetry(nfcA, cmd) ?: return null
                if (resp.size < 16) return null
                System.arraycopy(resp, 12, dump, targetPage * 4, 4)
                onProgress(targetPage + 1)
            }
            return dump
        } catch (e: Exception) {
            Log.w(TAG, "readTag failed", e)
            return null
        } finally {
            runCatching { nfcA.close() }
        }
    }

    private fun transceiveWithRetry(nfcA: NfcA, cmd: ByteArray): ByteArray? {
        for (attempt in 1..2) {
            try {
                return nfcA.transceive(cmd)
            } catch (e: Exception) {
                Log.w(TAG, "transceive attempt $attempt failed", e)
                try {
                    nfcA.close()
                    nfcA.connect()
                } catch (e2: Exception) {
                    return null
                }
            }
        }
        return null
    }

    /** POST the dump to the PC relay; returns null on success, error otherwise. */
    private fun postToPc(server: ServerConfig, dump: ByteArray): String? {
        return try {
            val url = URL("http://${server.ip}:${server.port}/inject")
            val conn = url.openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/json")
            if (server.token.isNotEmpty()) {
                conn.setRequestProperty("X-Auth-Token", server.token)
            }
            val body = JSONObject()
                .put("data_base64", Base64.encodeToString(dump, Base64.NO_WRAP))
                .toString()
            conn.outputStream.use { it.write(body.toByteArray()) }
            val code = conn.responseCode
            if (code in 200..299) null else "PC returned HTTP $code"
        } catch (e: Exception) {
            Log.w(TAG, "postToPc failed", e)
            "cannot reach ${server.ip}:${server.port}"
        }
    }

    private fun setStatus(message: String, error: Boolean = false) {
        statusText.text = message
        statusText.setTextColor(
            getColor(if (error) R.color.app_status_err else R.color.app_status_ok),
        )
        statusText.contentDescription = message
    }

    private fun vibrate(pattern: LongArray) {
        val vibrator = getSystemService(Vibrator::class.java) ?: return
        vibrator.vibrate(VibrationEffect.createWaveform(pattern, -1))
    }
}
