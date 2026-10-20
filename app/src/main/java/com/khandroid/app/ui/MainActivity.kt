package com.khandroid.app.ui

import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.List
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.khandroid.app.data.KhanDroidDatabase
import com.khandroid.app.net.CaptureConfig
import com.khandroid.app.service.KhanDroidService

data class InstalledApp(val label: String, val packageName: String)

class MainActivity : ComponentActivity() {

    private var pendingConfig: CaptureConfig? = null

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            pendingConfig?.let { launchService(it) }
        }
        pendingConfig = null
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val db = KhanDroidDatabase.get(this)
        val dao = db.httpExchangeDao()
        val tcpDao = db.tcpConnectionDao()
        val settings = DraftSettings()

        setContent {
            MaterialTheme {
                var tab by remember { mutableStateOf(0) }

                Scaffold(
                    bottomBar = {
                        NavigationBar {
                            NavigationBarItem(
                                selected = tab == 0, onClick = { tab = 0 },
                                icon = { Icon(Icons.Filled.PlayArrow, contentDescription = null) },
                                label = { Text("Capture") }
                            )
                            NavigationBarItem(
                                selected = tab == 1, onClick = { tab = 1 },
                                icon = { Icon(Icons.Filled.List, contentDescription = null) },
                                label = { Text("Sessions") }
                            )
                            NavigationBarItem(
                                selected = tab == 2, onClick = { tab = 2 },
                                icon = { Icon(Icons.Filled.Info, contentDescription = null) },
                                label = { Text("Connections") }
                            )
                            NavigationBarItem(
                                selected = tab == 3, onClick = { tab = 3 },
                                icon = { Icon(Icons.Filled.Settings, contentDescription = null) },
                                label = { Text("Settings") }
                            )
                        }
                    }
                ) { padding ->
                    Surface(modifier = Modifier.fillMaxSize().padding(padding)) {
                        when (tab) {
                            0 -> CaptureScreen(
                                apps = loadInstalledApps(),
                                settings = settings,
                                onStart = { partialCfg -> requestVpnAndStart(partialCfg, settings) },
                                onStop = { stopService(Intent(this, KhanDroidService::class.java)) }
                            )
                            1 -> SessionsScreen(dao)
                            2 -> ConnectionsScreen(tcpDao)
                            else -> SettingsScreen(this, settings)
                        }
                    }
                }
            }
        }
    }

    private fun requestVpnAndStart(partialCfg: CaptureConfig, settings: DraftSettings) {
        val cfg = partialCfg.copy(
            httpInspectionEnabled = settings.httpInspectionEnabled,
            mitmEnabled = settings.mitmEnabled,
            decryptCipher = settings.decryptCipher.takeIf { it != "None" },
            decryptKeyHex = settings.decryptKeyHex.takeIf { it.isNotBlank() },
            substitutionTableHex = settings.substitutionTableHex.takeIf { it.isNotBlank() }
        )
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            pendingConfig = cfg
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            launchService(cfg)
        }
    }

    private fun launchService(cfg: CaptureConfig) {
        val intent = Intent(this, KhanDroidService::class.java).putExtra(
            KhanDroidService.EXTRA_CONFIG, cfg
        )
        startForegroundService(intent)
    }

    private fun loadInstalledApps(): List<InstalledApp> {
        val pm = packageManager
        return pm.getInstalledApplications(PackageManager.GET_META_DATA)
            .filter { it.flags and ApplicationInfo.FLAG_SYSTEM == 0 } // user-installed apps only
            .map { InstalledApp(pm.getApplicationLabel(it).toString(), it.packageName) }
            .sortedBy { it.label.lowercase() }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CaptureScreen(
    apps: List<InstalledApp>,
    settings: DraftSettings,
    onStart: (CaptureConfig) -> Unit,
    onStop: () -> Unit
) {
    var appMenuExpanded by remember { mutableStateOf(false) }
    var running by remember { mutableStateOf(KhanDroidService.isRunning) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("KhanDroid", style = MaterialTheme.typography.headlineMedium)
        Text("Per-app, per-port capture \u00b7 HTTP/HTTPS inspection \u00b7 mandatory UDP export",
            style = MaterialTheme.typography.bodyMedium)

        ExposedDropdownMenuBox(
            expanded = appMenuExpanded,
            onExpandedChange = { appMenuExpanded = it }
        ) {
            OutlinedTextField(
                value = settings.selectedApp?.let { "${it.label} (${it.packageName})" } ?: "",
                onValueChange = {},
                readOnly = true,
                label = { Text("Target app") },
                modifier = Modifier.menuAnchor().fillMaxWidth()
            )
            ExposedDropdownMenu(
                expanded = appMenuExpanded,
                onDismissRequest = { appMenuExpanded = false }
            ) {
                Column(
                    modifier = Modifier
                        .heightIn(max = 320.dp)
                        .verticalScroll(rememberScrollState())
                ) {
                    for (app in apps) {
                        DropdownMenuItem(
                            text = { Text("${app.label} (${app.packageName})") },
                            onClick = {
                                settings.selectedApp = app
                                appMenuExpanded = false
                            }
                        )
                    }
                }
            }
        }

        OutlinedTextField(
            value = settings.portsText,
            onValueChange = { settings.portsText = it },
            label = { Text("Target ports (comma separated, blank = all)") },
            modifier = Modifier.fillMaxWidth()
        )

        OutlinedTextField(
            value = settings.udpHost,
            onValueChange = { settings.udpHost = it },
            label = { Text("UDP export host (your PC's LAN IP)") },
            modifier = Modifier.fillMaxWidth()
        )

        OutlinedTextField(
            value = settings.udpPortText,
            onValueChange = { settings.udpPortText = it },
            label = { Text("UDP export port") },
            modifier = Modifier.fillMaxWidth()
        )

        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(
                enabled = !running && settings.selectedApp != null && settings.udpHost.isNotBlank(),
                onClick = {
                    val ports = settings.portsText.split(",")
                        .mapNotNull { it.trim().toIntOrNull() }
                        .toSet()
                    val cfg = CaptureConfig(
                        targetPackage = settings.selectedApp!!.packageName,
                        targetPorts = ports,
                        udpHost = settings.udpHost.trim(),
                        udpPort = settings.udpPortText.toIntOrNull() ?: 5555
                    )
                    onStart(cfg)
                    running = true
                }
            ) { Text("Start") }

            OutlinedButton(
                enabled = running,
                onClick = {
                    onStop()
                    running = false
                }
            ) { Text("Stop") }
        }

        if (running) {
            Text(
                "Capturing\u2026 sent=${KhanDroidService.lastSent} dropped=${KhanDroidService.lastDropped}",
                style = MaterialTheme.typography.bodySmall
            )
        }

        Text(
            "TCP is terminated and relayed (best-effort, no retransmission). HTTP/HTTPS " +
                "inspection and custom decryption are configured in Settings.",
            style = MaterialTheme.typography.bodySmall
        )
    }
}
