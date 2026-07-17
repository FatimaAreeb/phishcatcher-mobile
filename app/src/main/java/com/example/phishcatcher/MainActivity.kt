package com.example.phishcatcher

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.net.URI
import kotlin.math.exp

// ============================================================
// FEATURE EXTRACTION — Kotlin port of the Python feature
// engineering from the original PhishCatcher (scikit-learn)
// ============================================================
object FeatureExtractor {

    private val SUSPICIOUS_KEYWORDS = listOf(
        "login", "verify", "account", "secure", "update", "confirm",
        "banking", "signin", "password", "credential", "wallet"
    )

    private val SHORTENERS = listOf(
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly"
    )

    private val IP_REGEX = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")

    data class Features(
        val urlLength: Double,
        val hostLength: Double,
        val pathLength: Double,
        val dotCount: Double,
        val hyphenCount: Double,
        val atSymbol: Double,
        val doubleSlashRedirect: Double,
        val hasIpHost: Double,
        val subdomainCount: Double,
        val usesHttps: Double,
        val digitRatio: Double,
        val specialCharCount: Double,
        val suspiciousKeywordCount: Double,
        val isShortener: Double,
        val queryLength: Double
    ) {
        fun toVector(): DoubleArray = doubleArrayOf(
            urlLength, hostLength, pathLength, dotCount, hyphenCount,
            atSymbol, doubleSlashRedirect, hasIpHost, subdomainCount,
            usesHttps, digitRatio, specialCharCount,
            suspiciousKeywordCount, isShortener, queryLength
        )
    }

    fun extract(rawUrl: String): Features {
        val urlString = if (rawUrl.contains("://")) rawUrl else "http://$rawUrl"
        val uri = runCatching { URI(urlString) }.getOrNull()

        val host = uri?.host ?: ""
        val path = uri?.path ?: ""
        val query = uri?.query ?: ""
        val lower = rawUrl.lowercase()

        val afterProtocol = urlString.substringAfter("://", urlString)

        return Features(
            urlLength = rawUrl.length.toDouble(),
            hostLength = host.length.toDouble(),
            pathLength = path.length.toDouble(),
            dotCount = rawUrl.count { it == '.' }.toDouble(),
            hyphenCount = rawUrl.count { it == '-' }.toDouble(),
            atSymbol = if (rawUrl.contains('@')) 1.0 else 0.0,
            doubleSlashRedirect = if (afterProtocol.contains("//")) 1.0 else 0.0,
            hasIpHost = if (IP_REGEX.matches(host)) 1.0 else 0.0,
            subdomainCount = if (host.isNotEmpty())
                (host.count { it == '.' } - 1).coerceAtLeast(0).toDouble() else 0.0,
            usesHttps = if (urlString.startsWith("https://")) 1.0 else 0.0,
            digitRatio = if (rawUrl.isNotEmpty())
                rawUrl.count { it.isDigit() }.toDouble() / rawUrl.length else 0.0,
            specialCharCount = rawUrl.count { it in "?%&=_" }.toDouble(),
            suspiciousKeywordCount = SUSPICIOUS_KEYWORDS.count { lower.contains(it) }.toDouble(),
            isShortener = if (SHORTENERS.any { host.equals(it, ignoreCase = true) }) 1.0 else 0.0,
            queryLength = query.length.toDouble()
        )
    }
}

// ============================================================
// CLASSIFIER — logistic regression on-device
// z = dot(weights, (x - mean) / scale) + intercept
// p(phishing) = 1 / (1 + e^-z)
// ============================================================
object PhishingClassifier {

    private val WEIGHTS = doubleArrayOf(
        0.65, 0.30, 0.25, 0.40, 0.55, 1.20, 0.80, 1.50,
        0.60, -0.70, 0.45, 0.35, 0.90, 1.10, 0.20
    )
    private const val INTERCEPT = -1.10

    private val SCALER_MEAN = DoubleArray(WEIGHTS.size) { 0.0 }
    private val SCALER_SCALE = doubleArrayOf(
        40.0, 15.0, 12.0, 3.0, 2.0, 1.0, 1.0, 1.0, 2.0, 1.0, 0.2, 4.0, 2.0, 1.0, 15.0
    )

    data class Result(
        val isPhishing: Boolean,
        val confidence: Double,
        val phishingProbability: Double,
        val topSignals: List<String>
    )

    private val FEATURE_NAMES = listOf(
        "URL length", "Host length", "Path length", "Dot count", "Hyphen count",
        "@ symbol in URL", "Double-slash redirect", "IP address as host",
        "Subdomain count", "Uses HTTPS", "Digit ratio", "Special characters",
        "Suspicious keywords", "URL shortener", "Query string length"
    )

    fun classify(url: String): Result {
        val x = FeatureExtractor.extract(url).toVector()

        var z = INTERCEPT
        val contributions = DoubleArray(x.size)
        for (i in x.indices) {
            val scaled = (x[i] - SCALER_MEAN[i]) / SCALER_SCALE[i]
            val c = WEIGHTS[i] * scaled
            contributions[i] = c
            z += c
        }

        val pPhish = 1.0 / (1.0 + exp(-z))
        val isPhishing = pPhish >= 0.5

        val topSignals = contributions
            .mapIndexed { i, c -> FEATURE_NAMES[i] to c }
            .filter { (_, c) -> if (isPhishing) c > 0 else c < 0 }
            .sortedByDescending { (_, c) -> kotlin.math.abs(c) }
            .take(3)
            .map { it.first }

        return Result(
            isPhishing = isPhishing,
            confidence = if (isPhishing) pPhish else 1.0 - pPhish,
            phishingProbability = pPhish,
            topSignals = topSignals
        )
    }
}

// ============================================================
// UI — Jetpack Compose
// ============================================================
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                PhishCatcherScreen()
            }
        }
    }
}

data class HistoryEntry(
    val url: String,
    val result: PhishingClassifier.Result
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PhishCatcherScreen() {
    var urlInput by remember { mutableStateOf("") }
    var currentResult by remember { mutableStateOf<PhishingClassifier.Result?>(null) }
    var checkedUrl by remember { mutableStateOf("") }
    val history = remember { mutableStateListOf<HistoryEntry>() }

    fun runCheck() {
        val url = urlInput.trim()
        if (url.isEmpty()) return
        val result = PhishingClassifier.classify(url)
        currentResult = result
        checkedUrl = url
        history.add(0, HistoryEntry(url, result))
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("PhishCatcher", fontWeight = FontWeight.Bold) }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .padding(16.dp)
                .fillMaxSize()
        ) {
            OutlinedTextField(
                value = urlInput,
                onValueChange = { urlInput = it },
                label = { Text("Enter a URL to check") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(Modifier.height(12.dp))

            Button(
                onClick = { runCheck() },
                enabled = urlInput.isNotBlank(),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Check URL")
            }

            Spacer(Modifier.height(16.dp))

            currentResult?.let { result ->
                ResultCard(checkedUrl, result)
                Spacer(Modifier.height(16.dp))
            }

            if (history.isNotEmpty()) {
                Text(
                    "History",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
                Spacer(Modifier.height(8.dp))
                LazyColumn {
                    items(history) { entry ->
                        HistoryRow(entry)
                        HorizontalDivider()
                    }
                }
            }
        }
    }
}

@Composable
fun ResultCard(url: String, result: PhishingClassifier.Result) {
    val verdictColor = if (result.isPhishing) Color(0xFFB3261E) else Color(0xFF2E7D32)
    val verdictText = if (result.isPhishing) "⚠ Likely Phishing" else "✓ Looks Safe"

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text(
                verdictText,
                color = verdictColor,
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold
            )
            Spacer(Modifier.height(4.dp))
            Text(url, style = MaterialTheme.typography.bodySmall, maxLines = 2)
            Spacer(Modifier.height(8.dp))
            Text(
                "Confidence: ${"%.1f".format(result.confidence * 100)}%",
                style = MaterialTheme.typography.bodyMedium
            )
            if (result.topSignals.isNotEmpty()) {
                Spacer(Modifier.height(8.dp))
                Text(
                    "Key signals:",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.SemiBold
                )
                result.topSignals.forEach { signal ->
                    Text("• $signal", style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

@Composable
fun HistoryRow(entry: HistoryEntry) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            if (entry.result.isPhishing) "⚠" else "✓",
            color = if (entry.result.isPhishing) Color(0xFFB3261E) else Color(0xFF2E7D32),
            fontSize = 18.sp,
            modifier = Modifier.padding(end = 12.dp)
        )
        Column(Modifier.weight(1f)) {
            Text(entry.url, style = MaterialTheme.typography.bodyMedium, maxLines = 1)
            Text(
                "${"%.0f".format(entry.result.confidence * 100)}% confident",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}