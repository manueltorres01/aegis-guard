@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.aegisguard.androidtest

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshots.SnapshotStateList
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { AegisGuardTestApp() }
    }
}

private enum class Screen(val title: String) {
    HOME("Inicio"), SCAN("Analizar"), RESULTS("Resultados"), SETTINGS("Ajustes")
}

private data class Finding(
    val id: String,
    val name: String,
    val path: String,
    val verdict: String,
    val score: Int,
    val reason: String
)

private val DemoFindings = listOf(
    Finding("1", "DiscordUpdater.apk", "/storage/emulated/0/Download", "suspicious", 31, "Paquete fuera de una tienda conocida; requiere revisión."),
    Finding("2", "game-mod.zip", "/storage/emulated/0/Download", "malicious", 78, "Contenido comprimido con script de ejecución."),
    Finding("3", "Fotos vacaciones.jpg", "/storage/emulated/0/Pictures", "clean", 0, "Archivo sin indicadores detectables."),
    Finding("4", "Aegis-demo.txt", "/storage/emulated/0/Documents", "not-analyzed", 0, "Todavía no se ha analizado."),
)

@Composable
private fun AegisGuardTestApp() {
    val colors = darkColorScheme(
        primary = Color(0xFF80CBC4),
        secondary = Color(0xFF9FA8DA),
        background = Color(0xFF08111F),
        surface = Color(0xFF111E31),
        surfaceVariant = Color(0xFF1B2B43),
        error = Color(0xFFFF8A80)
    )

    MaterialTheme(colorScheme = colors) {
        val findings = remember { mutableStateListOf(*DemoFindings.toTypedArray()) }
        var screen by rememberSaveable { mutableStateOf(Screen.HOME) }
        var scanning by rememberSaveable { mutableStateOf(false) }
        var progress by rememberSaveable { mutableFloatStateOf(0f) }
        var scanFinished by rememberSaveable { mutableStateOf(false) }

        LaunchedEffect(scanning) {
            if (scanning) {
                progress = 0f
                repeat(20) {
                    delay(120)
                    progress = (it + 1) / 20f
                }
                scanning = false
                scanFinished = true
            }
        }

        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text("Aegis Guard", fontWeight = FontWeight.Bold) },
                    navigationIcon = { Icon(Icons.Default.Security, contentDescription = null, tint = MaterialTheme.colorScheme.primary) }
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
            Surface(modifier = Modifier.fillMaxSize().padding(padding), color = MaterialTheme.colorScheme.background) {
                when (screen) {
                    Screen.HOME -> HomeScreen(findings, scanFinished, onScan = { screen = Screen.SCAN })
                    Screen.SCAN -> ScanScreen(scanning, progress, onStart = { scanning = true }, onResults = { screen = Screen.RESULTS })
                    Screen.RESULTS -> ResultsScreen(findings)
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
private fun HomeScreen(findings: SnapshotStateList<Finding>, scanFinished: Boolean, onScan: () -> Unit) {
    val threats = findings.count { it.verdict == "malicious" }
    val suspicious = findings.count { it.verdict == "suspicious" }
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text("Protección local", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
        Text("Prototipo Android de Aegis Guard. Todo lo que ves aquí es una simulación segura.", color = MaterialTheme.colorScheme.onSurfaceVariant)
        OutlinedCard(colors = CardDefaults.outlinedCardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(modifier = Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.CheckCircle, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(32.dp))
                    Spacer(Modifier.width(12.dp))
                    Column {
                        Text("Modo de prueba activo", fontWeight = FontWeight.Bold)
                        Text("No se modifican archivos ni se solicitan permisos peligrosos.", style = MaterialTheme.typography.bodySmall)
                    }
                }
                Button(onClick = onScan, modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Default.PlayArrow, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text("Analizar dispositivo")
                }
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
            MetricCard("Amenazas", threats.toString(), MaterialTheme.colorScheme.error, Modifier.weight(1f))
            MetricCard("Sospechosos", suspicious.toString(), Color(0xFFFFC107), Modifier.weight(1f))
        }
        OutlinedCard(colors = CardDefaults.outlinedCardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(modifier = Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(if (scanFinished) "Último análisis completado" else "Aún no hay un análisis real", fontWeight = FontWeight.Bold)
                Text("Los resultados de esta pantalla son datos de prueba para validar el flujo Android.", style = MaterialTheme.typography.bodySmall)
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
private fun ScanScreen(scanning: Boolean, progress: Float, onStart: () -> Unit, onResults: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text("Analizar", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
        Text("Selecciona un tipo de análisis. En esta versión solo se simula el proceso.", color = MaterialTheme.colorScheme.onSurfaceVariant)
        OutlinedCard(colors = CardDefaults.outlinedCardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(modifier = Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Análisis rápido", fontWeight = FontWeight.Bold)
                Text("Revisa una muestra de archivos de demostración y genera resultados explicables.", style = MaterialTheme.typography.bodySmall)
                AnimatedVisibility(visible = scanning) {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        LinearProgressIndicator(progress = { progress }, modifier = Modifier.fillMaxWidth())
                        Text("Analizando ${(progress * 100).toInt()}%", style = MaterialTheme.typography.labelMedium)
                    }
                }
                Button(onClick = onStart, enabled = !scanning, modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Default.PlayArrow, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text(if (scanning) "Analizando…" else "Iniciar análisis")
                }
                OutlinedButton(onClick = onResults, modifier = Modifier.fillMaxWidth()) { Text("Ver resultados de prueba") }
            }
        }
        Text("Próximamente: integración con almacenamiento Android mediante permisos explícitos y análisis local real.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun ResultsScreen(findings: SnapshotStateList<Finding>) {
    var filter by rememberSaveable { mutableStateOf("Todo") }
    val filters = listOf("Todo", "Sospechoso", "No analizado", "Malicioso")
    val visible = findings.filter {
        when (filter) {
            "Sospechoso" -> it.verdict == "suspicious"
            "No analizado" -> it.verdict == "not-analyzed"
            "Malicioso" -> it.verdict == "malicious"
            else -> true
        }
    }
    Column(modifier = Modifier.fillMaxSize().padding(horizontal = 20.dp)) {
        Spacer(Modifier.height(18.dp))
        Text("Resultados", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
        Text("${findings.size} elementos registrados", color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(modifier = Modifier.fillMaxWidth().padding(vertical = 14.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            filters.forEach { item ->
                FilterChip(selected = filter == item, onClick = { filter = item }, label = { Text(item) })
            }
        }
        LazyColumn(contentPadding = PaddingValues(bottom = 24.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            items(visible, key = { it.id }) { finding -> FindingCard(finding) }
        }
    }
}

@Composable
private fun FindingCard(finding: Finding) {
    val (label, color, icon) = when (finding.verdict) {
        "malicious" -> Triple("Malicioso", MaterialTheme.colorScheme.error, Icons.Default.Warning)
        "suspicious" -> Triple("Sospechoso", Color(0xFFFFC107), Icons.Default.Warning)
        "not-analyzed" -> Triple("No analizado", MaterialTheme.colorScheme.onSurfaceVariant, Icons.Default.Assessment)
        else -> Triple("Limpio", MaterialTheme.colorScheme.primary, Icons.Default.CheckCircle)
    }
    OutlinedCard(colors = CardDefaults.outlinedCardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(22.dp))
                Spacer(Modifier.width(8.dp))
                Text(finding.name, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                Text("$label · ${finding.score}/100", color = color, style = MaterialTheme.typography.labelMedium)
            }
            Text(finding.path, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(finding.reason, style = MaterialTheme.typography.bodySmall)
            if (finding.verdict == "malicious") OutlinedButton(onClick = {}, modifier = Modifier.fillMaxWidth()) { Text("Aislar (simulación)") }
        }
    }
}

@Composable
private fun SettingsScreen() {
    var protection by rememberSaveable { mutableStateOf(true) }
    var reputation by rememberSaveable { mutableStateOf(false) }
    Column(modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Text("Ajustes", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
        SettingRow("Protección de prueba", "Activa la simulación de monitorización local.", protection) { protection = it }
        SettingRow("Consultas de reputación", "Desactivadas por defecto; solo enviarían hashes con consentimiento.", reputation) { reputation = it }
        OutlinedCard(colors = CardDefaults.outlinedCardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Privacidad", fontWeight = FontWeight.Bold)
                Text("Este prototipo no solicita acceso a Internet, cámara, contactos ni ubicación.", style = MaterialTheme.typography.bodySmall)
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
