@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.aegisguard.android

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Assessment
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Create
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AssistChip
import androidx.compose.material3.BottomAppBar
import androidx.compose.material3.Button
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.documentfile.provider.DocumentFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant
import java.util.Locale

private const val MAX_FILES = 2_000
private const val MAX_DEPTH = 8
private const val MAX_HASH_BYTES = 8L * 1024 * 1024
private const val REPORT_FILE = "last-scan.json"

class MainActivity : ComponentActivity() {
    private var selectedTreeUri by mutableStateOf<String?>(null)
    private var pendingReportJson: String? = null

    private val folderPicker = registerForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
        if (uri == null) return@registerForActivityResult
        try {
            contentResolver.takePersistableUriPermission(
                uri,
                android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION
            )
        } catch (_: SecurityException) {
            // Some document providers do not expose persistable grants. The selected folder
            // remains usable for this session and is still stored as a best-effort preference.
        }
        selectedTreeUri = uri.toString()
        getPreferences(MODE_PRIVATE).edit().putString("tree_uri", selectedTreeUri).apply()
    }

    private val reportPicker = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/json")
    ) { uri ->
        val report = pendingReportJson ?: return@registerForActivityResult
        if (uri != null) {
            runCatching {
                contentResolver.openOutputStream(uri)?.use { output ->
                    output.write(report.toByteArray(StandardCharsets.UTF_8))
                }
            }
        }
        pendingReportJson = null
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        selectedTreeUri = getPreferences(MODE_PRIVATE).getString("tree_uri", null)
        setContent {
            AegisGuardApp(
                initialTreeUri = selectedTreeUri,
                onPickFolder = { folderPicker.launch(null) },
                onExportReport = { folder, findings, scannedAt ->
                    pendingReportJson = buildReportJson(folder, findings, scannedAt)
                    reportPicker.launch("aegis-guard-report.json")
                }
            )
        }
    }
}

private enum class Screen(val title: String) {
    HOME("Inicio"),
    SCAN("Analizar"),
    RESULTS("Resultados"),
    SETTINGS("Ajustes")
}

private enum class Verdict(val wire: String, val label: String) {
    CLEAN("clean", "Limpio"),
    SUSPICIOUS("suspicious", "Sospechoso"),
    MALICIOUS("malicious", "Malicioso"),
    NOT_ANALYZED("not-analyzed", "No analizado")
}

private data class Finding(
    val id: String,
    val name: String,
    val path: String,
    val verdict: Verdict,
    val score: Int,
    val reason: String,
    val sizeBytes: Long = 0,
    val sha256: String? = null
)

private data class ScanProgress(val scanned: Int, val limited: Boolean)

private data class ScanSummary(
    val findings: List<Finding>,
    val scanned: Int,
    val durationMs: Long,
    val limited: Boolean
)

@Composable
private fun AegisGuardApp(
    initialTreeUri: String?,
    onPickFolder: () -> Unit,
    onExportReport: (String?, List<Finding>, String?) -> Unit
) {
    val context = LocalContext.current
    val colors = darkColorScheme(
        primary = Color(0xFF80CBC4),
        secondary = Color(0xFF9FA8DA),
        background = Color(0xFF08111F),
        surface = Color(0xFF111E31),
        surfaceVariant = Color(0xFF1B2B43),
        error = Color(0xFFFF8A80)
    )

    MaterialTheme(colorScheme = colors) {
        var screen by rememberSaveable { mutableStateOf(Screen.HOME) }
        var findings by remember { mutableStateOf(emptyList<Finding>()) }
        var selectedUri by rememberSaveable { mutableStateOf(initialTreeUri) }
        var scanning by rememberSaveable { mutableStateOf(false) }
        var progress by rememberSaveable { mutableFloatStateOf(0f) }
        var scannedFiles by rememberSaveable { mutableIntStateOf(0) }
        var scanFinished by rememberSaveable { mutableStateOf(false) }
        var scanMessage by rememberSaveable { mutableStateOf("Selecciona una carpeta para empezar.") }
        var lastScanAt by rememberSaveable { mutableStateOf<String?>(null) }
        val scope = rememberCoroutineScope()
        var scanJob by remember { mutableStateOf<Job?>(null) }

        LaunchedEffect(Unit) {
            val saved = withContext(Dispatchers.IO) { readReport(context.filesDir) }
            if (saved != null) {
                findings = saved.first
                lastScanAt = saved.second
                scanFinished = true
                scanMessage = "Se ha restaurado el último análisis local."
            }
        }

        LaunchedEffect(initialTreeUri) {
            selectedUri = initialTreeUri
        }

        fun startScan() {
            val uriText = selectedUri
            if (uriText.isNullOrBlank()) {
                scanMessage = "Selecciona primero una carpeta del dispositivo."
                screen = Screen.SCAN
                return
            }
            scanJob?.cancel()
            scanJob = scope.launch {
                scanning = true
                scanFinished = false
                progress = 0f
                scannedFiles = 0
                scanMessage = "Analizando archivos localmente…"
                val started = System.currentTimeMillis()
                try {
                    val summary = scanTree(context, Uri.parse(uriText)) { update ->
                        scannedFiles = update.scanned
                        progress = (update.scanned.toFloat() / MAX_FILES).coerceAtMost(0.98f)
                    }
                    findings = summary.findings
                    progress = 1f
                    scannedFiles = summary.scanned
                    scanFinished = true
                    lastScanAt = Instant.now().toString()
                    scanMessage = if (summary.limited) {
                        "Se alcanzó el límite seguro de $MAX_FILES archivos; puedes analizar otra carpeta."
                    } else {
                        "Análisis completado en ${summary.durationMs} ms."
                    }
                    withContext(Dispatchers.IO) {
                        writeReport(context.filesDir, selectedUri, findings, lastScanAt)
                    }
                } catch (error: kotlinx.coroutines.CancellationException) {
                    throw error
                } catch (error: Throwable) {
                    scanMessage = "No se pudo analizar la carpeta: ${error.message ?: "acceso no disponible"}."
                }
                scanning = false
            }
        }

        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text("Aegis Guard", fontWeight = FontWeight.Bold) },
                    navigationIcon = {
                        Icon(Icons.Default.Security, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                    }
                )
            },
            bottomBar = {
                BottomAppBar(modifier = Modifier.navigationBarsPadding()) {
                    Screen.entries.forEach { item ->
                        NavigationBarItem(
                            selected = screen == item,
                            onClick = { screen = item },
                            icon = { Icon(item.icon(), contentDescription = item.title) },
                            label = { Text(item.title) }
                        )
                    }
                }
            }
        ) { padding ->
            Surface(
                modifier = Modifier.fillMaxSize().padding(padding),
                color = MaterialTheme.colorScheme.background
            ) {
                when (screen) {
                    Screen.HOME -> HomeScreen(
                        findings = findings,
                        selectedUri = selectedUri,
                        scanFinished = scanFinished,
                        onScan = { screen = Screen.SCAN },
                        onPickFolder = onPickFolder
                    )
                    Screen.SCAN -> ScanScreen(
                        selectedUri = selectedUri,
                        scanning = scanning,
                        progress = progress,
                        scannedFiles = scannedFiles,
                        message = scanMessage,
                        onPickFolder = onPickFolder,
                        onStart = ::startScan,
                        onResults = { screen = Screen.RESULTS }
                    )
                    Screen.RESULTS -> ResultsScreen(
                        findings = findings,
                        folder = selectedUri,
                        lastScanAt = lastScanAt,
                        onExportReport = { onExportReport(selectedUri, findings, lastScanAt) }
                    )
                    Screen.SETTINGS -> SettingsScreen()
                }
            }
        }
    }
}

private fun Screen.icon() = when (this) {
    Screen.HOME -> Icons.Default.Home
    Screen.SCAN -> Icons.Default.PlayArrow
    Screen.RESULTS -> Icons.Default.Assessment
    Screen.SETTINGS -> Icons.Default.Settings
}

@Composable
private fun HomeScreen(
    findings: List<Finding>,
    selectedUri: String?,
    scanFinished: Boolean,
    onScan: () -> Unit,
    onPickFolder: () -> Unit
) {
    val threats = findings.count { it.verdict == Verdict.MALICIOUS }
    val suspicious = findings.count { it.verdict == Verdict.SUSPICIOUS }
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text("Protección local", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
        Text(
            "Primera versión Android de Aegis Guard. El análisis se realiza en el dispositivo y no sube archivos.",
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        OutlinedCard(colors = CardDefaults.outlinedCardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(modifier = Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.CheckCircle, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(32.dp))
                    Spacer(Modifier.width(12.dp))
                    Column {
                        Text("Protección local lista", fontWeight = FontWeight.Bold)
                        Text("Solo se usa la carpeta que elijas y el acceso se puede revocar desde Android.", style = MaterialTheme.typography.bodySmall)
                    }
                }
                Button(onClick = onScan, modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Default.PlayArrow, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text("Analizar dispositivo")
                }
                OutlinedButton(onClick = onPickFolder, modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Default.FolderOpen, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text(if (selectedUri == null) "Elegir carpeta" else "Cambiar carpeta")
                }
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
            MetricCard("Amenazas", threats.toString(), MaterialTheme.colorScheme.error, Modifier.weight(1f))
            MetricCard("Sospechosos", suspicious.toString(), Color(0xFFFFC107), Modifier.weight(1f))
        }
        OutlinedCard(colors = CardDefaults.outlinedCardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(modifier = Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(if (scanFinished) "Último análisis guardado" else "Aún no hay un análisis", fontWeight = FontWeight.Bold)
                Text(
                    if (selectedUri == null) "Elige una carpeta para comenzar." else "La carpeta seleccionada se mantiene en el almacenamiento seguro de la aplicación.",
                    style = MaterialTheme.typography.bodySmall
                )
                AssistChip(onClick = {}, label = { Text("Sin conexión a la nube") })
            }
        }
    }
}

@Composable
private fun MetricCard(label: String, value: String, color: Color, modifier: Modifier) {
    OutlinedCard(modifier = modifier, colors = CardDefaults.outlinedCardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(value, fontSize = 30.sp, fontWeight = FontWeight.Bold, color = color)
            Text(label, style = MaterialTheme.typography.labelLarge)
        }
    }
}

@Composable
private fun ScanScreen(
    selectedUri: String?,
    scanning: Boolean,
    progress: Float,
    scannedFiles: Int,
    message: String,
    onPickFolder: () -> Unit,
    onStart: () -> Unit,
    onResults: () -> Unit
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text("Analizar", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
        Text(
            "Elige una carpeta y revisaremos sus archivos localmente con límites de consumo seguros.",
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        OutlinedCard(colors = CardDefaults.outlinedCardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(modifier = Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(if (selectedUri == null) "Ninguna carpeta seleccionada" else "Carpeta lista para analizar", fontWeight = FontWeight.Bold)
                Text(message, style = MaterialTheme.typography.bodySmall)
                AnimatedVisibility(visible = scanning) {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        LinearProgressIndicator(progress = { progress }, modifier = Modifier.fillMaxWidth())
                        Text("Analizados $scannedFiles archivos", style = MaterialTheme.typography.labelMedium)
                    }
                }
                Button(onClick = onPickFolder, enabled = !scanning, modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Default.FolderOpen, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text("Elegir carpeta")
                }
                Button(onClick = onStart, enabled = !scanning && selectedUri != null, modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Default.PlayArrow, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text(if (scanning) "Analizando…" else "Iniciar análisis")
                }
                OutlinedButton(onClick = onResults, modifier = Modifier.fillMaxWidth()) { Text("Ver resultados") }
            }
        }
        Text(
            "Los nombres de archivo con indicadores claros se clasifican como maliciosos; extensiones ejecutables se mantienen como sospechosas para reducir falsos positivos.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun ResultsScreen(
    findings: List<Finding>,
    folder: String?,
    lastScanAt: String?,
    onExportReport: () -> Unit
) {
    var filter by rememberSaveable { mutableStateOf("Todo") }
    val filters = listOf("Todo", "Sospechoso", "No analizado", "Malicioso")
    val visible = findings.filter {
        when (filter) {
            "Sospechoso" -> it.verdict == Verdict.SUSPICIOUS
            "No analizado" -> it.verdict == Verdict.NOT_ANALYZED
            "Malicioso" -> it.verdict == Verdict.MALICIOUS
            else -> true
        }
    }
    Column(modifier = Modifier.fillMaxSize().padding(horizontal = 20.dp)) {
        Spacer(Modifier.height(18.dp))
        Text("Resultados", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
        Text("${findings.size} archivos registrados", color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(modifier = Modifier.fillMaxWidth().padding(vertical = 14.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            filters.forEach { item ->
                FilterChip(selected = filter == item, onClick = { filter = item }, label = { Text(item) })
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp)) {
            OutlinedButton(onClick = onExportReport, enabled = findings.isNotEmpty(), modifier = Modifier.weight(1f)) {
                Icon(Icons.Default.Create, contentDescription = null)
                Spacer(Modifier.width(6.dp))
                Text("Exportar informe")
            }
        }
        if (folder != null) {
            Text("Origen: ${shortenUri(folder)}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        if (lastScanAt != null) {
            Text("Último análisis: $lastScanAt", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        if (visible.isEmpty()) {
            Text("No hay elementos en este filtro.", modifier = Modifier.padding(top = 20.dp), color = MaterialTheme.colorScheme.onSurfaceVariant)
        } else {
            LazyColumn(contentPadding = PaddingValues(bottom = 24.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                items(visible, key = { it.id }) { finding -> FindingCard(finding) }
            }
        }
    }
}

@Composable
private fun FindingCard(finding: Finding) {
    val (color, icon) = when (finding.verdict) {
        Verdict.MALICIOUS -> MaterialTheme.colorScheme.error to Icons.Default.Warning
        Verdict.SUSPICIOUS -> Color(0xFFFFC107) to Icons.Default.Warning
        Verdict.NOT_ANALYZED -> MaterialTheme.colorScheme.onSurfaceVariant to Icons.Default.Assessment
        Verdict.CLEAN -> MaterialTheme.colorScheme.primary to Icons.Default.CheckCircle
    }
    OutlinedCard(colors = CardDefaults.outlinedCardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(22.dp))
                Spacer(Modifier.width(8.dp))
                Text(finding.name, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                Text("${finding.verdict.label} · ${finding.score}/100", color = color, style = MaterialTheme.typography.labelMedium)
            }
            Text(shortenUri(finding.path), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(finding.reason, style = MaterialTheme.typography.bodySmall)
            if (finding.sha256 != null) {
                Text("SHA-256: ${finding.sha256}", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
private fun SettingsScreen() {
    var protection by rememberSaveable { mutableStateOf(true) }
    var reputation by rememberSaveable { mutableStateOf(false) }
    Column(modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Text("Ajustes", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
        SettingRow("Protección local", "Activa el análisis bajo demanda de la carpeta seleccionada.", protection) { protection = it }
        SettingRow("Consultas de reputación", "Desactivadas por defecto; solo enviarían hashes con consentimiento.", reputation) { reputation = it }
        OutlinedCard(colors = CardDefaults.outlinedCardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Privacidad y límites", fontWeight = FontWeight.Bold)
                Text("La app no solicita acceso global al almacenamiento, no usa red y limita cada análisis a $MAX_FILES archivos.", style = MaterialTheme.typography.bodySmall)
                Text("Versión Android 1.0.0", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
            }
        }
    }
}

@Composable
private fun SettingRow(title: String, description: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    OutlinedCard(colors = CardDefaults.outlinedCardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Row(modifier = Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(title, fontWeight = FontWeight.Bold)
                Text(description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Switch(checked = checked, onCheckedChange = onCheckedChange)
        }
    }
}

private suspend fun scanTree(
    context: Context,
    rootUri: Uri,
    onProgress: suspend (ScanProgress) -> Unit
): ScanSummary = withContext(Dispatchers.IO) {
    val started = System.currentTimeMillis()
    val root = DocumentFile.fromTreeUri(context, rootUri)
        ?: error("el proveedor no permite acceder a esta carpeta")
    val findings = mutableListOf<Finding>()
    var scanned = 0
    var limited = false

    suspend fun visit(directory: DocumentFile, depth: Int) {
        ensureActive()
        if (depth > MAX_DEPTH || scanned >= MAX_FILES) {
            limited = true
            return
        }
        val children = runCatching { directory.listFiles().toList() }.getOrElse {
            findings += unreadableFinding(directory.uri, directory.name ?: "Carpeta")
            return
        }
        for (child in children) {
            ensureActive()
            if (scanned >= MAX_FILES) {
                limited = true
                break
            }
            if (child.isDirectory) {
                visit(child, depth + 1)
            } else if (child.isFile) {
                findings += inspectFile(context.contentResolver, child)
                scanned += 1
                onProgress(ScanProgress(scanned, limited))
            }
        }
    }

    visit(root, 0)
    ScanSummary(findings, scanned, System.currentTimeMillis() - started, limited)
}

private fun inspectFile(resolver: ContentResolver, document: DocumentFile): Finding {
    val name = document.name ?: "Archivo sin nombre"
    val lowerName = name.lowercase(Locale.ROOT)
    val classification = classifyName(lowerName)
    val size = document.length().coerceAtLeast(0L)
    val hash = if (size <= MAX_HASH_BYTES) sha256(resolver, document.uri) else null
    val reason = if (hash == null && size > MAX_HASH_BYTES) {
        "${classification.second} Hash omitido por superar el límite de consumo seguro."
    } else {
        classification.second
    }
    return Finding(
        id = document.uri.toString(),
        name = name,
        path = document.uri.toString(),
        verdict = classification.first,
        score = classification.third,
        reason = reason,
        sizeBytes = size,
        sha256 = hash
    )
}

private fun classifyName(name: String): Triple<Verdict, String, Int> {
    val highRisk = listOf("ransom", "stealer", "trojan", "backdoor", "keylogger", "spyware", "payload", "miner")
    val reviewTerms = listOf("crack", "keygen", "cheat", "patched", "unlocker", "modded")
    val executableExtensions = setOf("apk", "dex", "jar", "js", "mjs", "vbs", "ps1", "sh", "bat", "cmd", "scr", "msi")
    return when {
        highRisk.any(name::contains) -> Triple(
            Verdict.MALICIOUS,
            "El nombre contiene un indicador de alto riesgo; necesita confirmación antes de abrirse.",
            82
        )
        reviewTerms.any(name::contains) -> Triple(
            Verdict.SUSPICIOUS,
            "El nombre sugiere una modificación o herramienta no oficial; se mantiene como sospechoso, no como malware confirmado.",
            52
        )
        executableExtensions.any { name.substringAfterLast('.', "") == it } -> Triple(
            Verdict.SUSPICIOUS,
            "Archivo ejecutable o instalable; requiere reputación adicional para emitir un veredicto.",
            28
        )
        else -> Triple(Verdict.CLEAN, "No se encontraron indicadores de nombre en esta revisión local.", 0)
    }
}

private fun unreadableFinding(uri: Uri, name: String) = Finding(
    id = uri.toString(),
    name = name,
    path = uri.toString(),
    verdict = Verdict.NOT_ANALYZED,
    score = 0,
    reason = "No se pudo leer el elemento con el permiso concedido; no se marca como malicioso."
)

private fun sha256(resolver: ContentResolver, uri: Uri): String? = runCatching {
    val digest = MessageDigest.getInstance("SHA-256")
    resolver.openInputStream(uri)?.use { input ->
        val buffer = ByteArray(64 * 1024)
        while (true) {
            val read = input.read(buffer)
            if (read <= 0) break
            digest.update(buffer, 0, read)
        }
    } ?: return null
    digest.digest().joinToString("") { byte -> "%02x".format(byte) }
}.getOrNull()

private fun buildReportJson(folder: String?, findings: List<Finding>, scannedAt: String?): String {
    val files = JSONArray()
    findings.forEach { finding ->
        files.put(JSONObject().apply {
            put("id", finding.id)
            put("name", finding.name)
            put("path", finding.path)
            put("verdict", finding.verdict.wire)
            put("score", finding.score)
            put("reason", finding.reason)
            put("sizeBytes", finding.sizeBytes)
            put("sha256", finding.sha256 ?: JSONObject.NULL)
        })
    }
    return JSONObject().apply {
        put("product", "Aegis Guard Android")
        put("version", "1.0.0")
        put("generatedAt", Instant.now().toString())
        put("scannedAt", scannedAt ?: JSONObject.NULL)
        put("folder", folder ?: JSONObject.NULL)
        put("files", files)
    }.toString(2)
}

private fun writeReport(filesDir: File, folder: String?, findings: List<Finding>, scannedAt: String?) {
    runCatching {
        File(filesDir, REPORT_FILE).writeText(buildReportJson(folder, findings.take(MAX_FILES), scannedAt), StandardCharsets.UTF_8)
    }
}

private fun readReport(filesDir: File): Pair<List<Finding>, String?>? = runCatching {
    val file = File(filesDir, REPORT_FILE)
    if (!file.exists()) return null
    val root = JSONObject(file.readText(StandardCharsets.UTF_8))
    val array = root.optJSONArray("files") ?: JSONArray()
    val findings = buildList {
        for (index in 0 until array.length()) {
            val item = array.getJSONObject(index)
            val verdict = Verdict.entries.firstOrNull { it.wire == item.optString("verdict") } ?: Verdict.NOT_ANALYZED
            add(Finding(
                id = item.optString("id"),
                name = item.optString("name"),
                path = item.optString("path"),
                verdict = verdict,
                score = item.optInt("score"),
                reason = item.optString("reason"),
                sizeBytes = item.optLong("sizeBytes"),
                sha256 = item.optString("sha256").takeIf { it.isNotBlank() && it != "null" }
            ))
        }
    }
    findings to root.optString("scannedAt").takeIf { it.isNotBlank() && it != "null" }
}.getOrNull()

private fun shortenUri(value: String): String = if (value.length > 72) "…${value.takeLast(69)}" else value
