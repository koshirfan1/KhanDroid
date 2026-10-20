package com.khandroid.app.ui

import android.content.Context
import android.content.Intent
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import com.khandroid.app.net.tls.CaManager

/** Shared, in-memory draft settings for the current run. Not persisted across app restarts. */
class DraftSettings {
    var httpInspectionEnabled by mutableStateOf(true)
    var mitmEnabled by mutableStateOf(false)
    var decryptCipher by mutableStateOf("None") // "None" | "XOR" | "XXTEA" | "Substitution-256"
    var decryptKeyHex by mutableStateOf("")
    var substitutionTableHex by mutableStateOf("")

    var selectedApp by mutableStateOf<InstalledApp?>(null)
    var portsText by mutableStateOf("443")
    var udpHost by mutableStateOf("")
    var udpPortText by mutableStateOf("5555")
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(context: Context, settings: DraftSettings) {
    var cipherMenuExpanded by remember { mutableStateOf(false) }
    val cipherOptions = listOf("None", "XOR", "XXTEA", "Substitution-256", "Foxuc-Substitution", "Foxuc-XXTEA")

    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("Settings", style = MaterialTheme.typography.headlineMedium)

        Text("HTTP / HTTPS inspection", style = MaterialTheme.typography.titleMedium)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Switch(checked = settings.httpInspectionEnabled, onCheckedChange = { settings.httpInspectionEnabled = it })
            Spacer(Modifier.width(8.dp))
            Text("Tap plain HTTP and show request/response in Sessions")
        }

        Row(verticalAlignment = Alignment.CenterVertically) {
            Switch(checked = settings.mitmEnabled, onCheckedChange = { settings.mitmEnabled = it })
            Spacer(Modifier.width(8.dp))
            Text("Decrypt HTTPS (MITM) \u2014 experimental, see README")
        }

        OutlinedButton(onClick = { exportAndShareCa(context) }) {
            Text("Export & install KhanDroid CA certificate")
        }
        Text(
            "Required once, only if HTTPS decryption is on. Installs under " +
                "Settings > Security > Encryption & credentials > Install a certificate. " +
                "Apps using certificate pinning will still show as errors, not decrypted traffic.",
            style = MaterialTheme.typography.bodySmall
        )

        HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

        Text("Custom payload decryption", style = MaterialTheme.typography.titleMedium)
        Text(
            "For apps that layer their own lightweight encryption on top of HTTP bodies. " +
                "Generic algorithms only \u2014 for your own app or an authorized test target.",
            style = MaterialTheme.typography.bodySmall
        )

        ExposedDropdownMenuBox(expanded = cipherMenuExpanded, onExpandedChange = { cipherMenuExpanded = it }) {
            OutlinedTextField(
                value = settings.decryptCipher,
                onValueChange = {},
                readOnly = true,
                label = { Text("Cipher") },
                modifier = Modifier.menuAnchor().fillMaxWidth()
            )
            ExposedDropdownMenu(expanded = cipherMenuExpanded, onDismissRequest = { cipherMenuExpanded = false }) {
                cipherOptions.forEach { opt ->
                    DropdownMenuItem(text = { Text(opt) }, onClick = {
                        settings.decryptCipher = opt
                        cipherMenuExpanded = false
                    })
                }
            }
        }

        when (settings.decryptCipher) {
            "XOR", "XXTEA" -> OutlinedTextField(
                value = settings.decryptKeyHex,
                onValueChange = { settings.decryptKeyHex = it },
                label = {
                    Text(
                        if (settings.decryptCipher == "XXTEA") "Key (hex, 32 chars = 16 bytes)"
                        else "Key (hex, any length)"
                    )
                },
                modifier = Modifier.fillMaxWidth()
            )
            "Substitution-256" -> OutlinedTextField(
                value = settings.substitutionTableHex,
                onValueChange = { settings.substitutionTableHex = it },
                label = { Text("S-box table (hex, 512 chars = 256 bytes)") },
                modifier = Modifier.fillMaxWidth()
            )
        }

        Spacer(Modifier.height(4.dp))
        Text("DTC Game App Presets", style = MaterialTheme.typography.titleSmall)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = {
                settings.decryptCipher = "XXTEA"
                settings.decryptKeyHex = "4d42434c49454e545f21323031360000"
            }) {
                Text("XXTEA")
            }
            OutlinedButton(onClick = {
                settings.decryptCipher = "XOR"
                settings.decryptKeyHex = "70"
            }) {
                Text("XOR")
            }
            OutlinedButton(onClick = {
                settings.decryptCipher = "Foxuc-XXTEA"
                settings.decryptKeyHex = "4d42434c49454e545f21323031360000"
            }) {
                Text("Foxuc-XXTEA")
            }
        }
    }
}

private fun exportAndShareCa(context: Context) {
    val file = CaManager(context).exportCaCertPem()
    val uri = FileProvider.getUriForFile(context, "com.khandroid.app.fileprovider", file)
    val intent = Intent(Intent.ACTION_VIEW).apply {
        setDataAndType(uri, "application/x-x509-ca-cert")
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
    runCatching { context.startActivity(intent) }.onFailure {
        // Fall back to a generic share sheet if nothing handles the cert mime type directly.
        val shareIntent = Intent(Intent.ACTION_SEND).apply {
            type = "application/x-x509-ca-cert"
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        context.startActivity(Intent.createChooser(shareIntent, "Install KhanDroid CA").apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        })
    }
}
