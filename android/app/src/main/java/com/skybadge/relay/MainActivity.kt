package com.skybadge.relay

import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.NfcA
import android.os.Build
import android.os.Bundle
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
        private const val TRANSCEIVE_TIMEOUT_MS = 250
        private const val READ_DEADLINE_MS = 10000L
        private const val NTAG_PAGES = 135 // NTAG215: pages 0..134, 4 bytes each
        private const val NTAG_TOTAL = NTAG_PAGES * 4
        private val VIB_SUCCESS = longArrayOf(0, 120)
        private val VIB_ERROR = longArrayOf(0, 80, 120, 80)
    }

    private var nfcAdapter: NfcAdapter? = null
    private var readerModeEnabled = false
    private val executor = Executors.newSingleThreadExecutor()

    private lateinit var statusText: TextView
    private lateinit var ipEdit: TextInputEditText
    private lateinit var portEdit: TextInputEditText
    private lateinit var tokenEdit: TextInputEditText
    private lateinit var saveButton: Button

    @Volatile
    private var lastScanAt = 0L

    @Volatile
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

    private fun onTagDiscovered(tag: Tag) {
        val now = System.currentTimeMillis()
        if (busy || now - lastScanAt < DEBOUNCE_MS) return
        lastScanAt = now
        busy = true

        val server = buildServerConfig()
        if (server == null) {
            busy = false
            setStatus(getString(R.string.status_error, "enter the PC IP first"), error = true)
            vibrate(VIB_ERROR)
            return
        }

        val uidHex = tag.id.joinToString("") { "%02x".format(it) }.uppercase()
        setStatus(getString(R.string.status_reading, uidHex))
        executor.execute {
            val dump = readTag(tag) { page ->
                runOnUiThread {
                    setStatus(getString(R.string.status_reading_progress, page, NTAG_PAGES, uidHex))
                }
            }
            if (dump == null) {
                runOnUiThread {
                    busy = false
                    setStatus(
                        getString(R.string.status_error, "badge read failed (keep it still on the phone)"),
                        error = true,
                    )
                    vibrate(VIB_ERROR)
                }
                return@execute
            }
            runOnUiThread { setStatus(getString(R.string.status_sending, uidHex)) }
            val err = postToPc(server, dump)
            runOnUiThread {
                busy = false
                if (err == null) {
                    setStatus(getString(R.string.status_sent, uidHex))
                    vibrate(VIB_SUCCESS)
                } else {
                    setStatus(getString(R.string.status_error, err), error = true)
                    vibrate(VIB_ERROR)
                }
            }
        }
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

    /** Read all NTAG215 pages via NfcA READ (0x30); returns 540 bytes or null. */
    private fun readTag(tag: Tag, onProgress: (Int) -> Unit): ByteArray? {
        val nfcA = NfcA.get(tag) ?: return null
        nfcA.timeout = TRANSCEIVE_TIMEOUT_MS
        val deadline = System.currentTimeMillis() + READ_DEADLINE_MS
        try {
            nfcA.connect()
            val dump = ByteArray(NTAG_TOTAL)
            for (page in 0 until NTAG_PAGES) {
                if (System.currentTimeMillis() > deadline) return null
                val cmd = byteArrayOf(0x30.toByte(), page.toByte())
                val resp = transceiveWithRetry(nfcA, cmd) ?: return null
                if (resp.size < 4) return null
                System.arraycopy(resp, 0, dump, page * 4, 4)
                if (page % 15 == 0 || page == NTAG_PAGES - 1) onProgress(page + 1)
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
