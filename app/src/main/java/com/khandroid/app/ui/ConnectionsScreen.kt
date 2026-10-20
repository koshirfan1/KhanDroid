package com.khandroid.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.khandroid.app.data.TcpConnectionDao
import com.khandroid.app.data.TcpConnectionEntity
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConnectionsScreen(dao: TcpConnectionDao) {
    val connections by dao.observeAll().collectAsState(initial = emptyList())
    var selectedConnection by remember { mutableStateOf<TcpConnectionEntity?>(null) }
    val scope = rememberCoroutineScope()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Active Connections (PCapDroid)") },
                actions = {
                    IconButton(onClick = { scope.launch { dao.clearAll() } }) {
                        Icon(Icons.Filled.Delete, contentDescription = "Clear Connections")
                    }
                }
            )
        }
    ) { padding ->
        if (connections.isEmpty()) {
            Box(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentAlignment = Alignment.Center
            ) {
                Text("No TCP connections recorded yet.\nStart capture and generate traffic in the target app.",
                    style = MaterialTheme.typography.bodyMedium)
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize().padding(padding).padding(horizontal = 16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(connections) { conn ->
                    ConnectionCard(conn) { selectedConnection = conn }
                }
            }
        }

        selectedConnection?.let { conn ->
            ConnectionDetailDialog(conn) { selectedConnection = null }
        }
    }
}

@Composable
fun ConnectionCard(conn: TcpConnectionEntity, onClick: () -> Unit) {
    val timeStr = remember(conn.time) {
        SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(conn.time))
    }
    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text("${conn.protocol} \u2192 ${conn.remoteHost}:${conn.remotePort}",
                    style = MaterialTheme.typography.titleMedium)
                Text(timeStr, style = MaterialTheme.typography.bodySmall)
            }
            Spacer(modifier = Modifier.height(4.dp))
            Text("Local Port: ${conn.localPort} | Sent: ${conn.bytesSent} B | Recv: ${conn.bytesReceived} B",
                style = MaterialTheme.typography.bodySmall)
            if (conn.rawStreamPreview.isNotBlank()) {
                Spacer(modifier = Modifier.height(4.dp))
                Text("Preview: ${conn.rawStreamPreview.take(60)}...",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace)
            }
        }
    }
}

@Composable
fun ConnectionDetailDialog(conn: TcpConnectionEntity, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("${conn.protocol} Connection: ${conn.remoteHost}:${conn.remotePort}") },
        text = {
            Column(modifier = Modifier.fillMaxWidth().heightIn(max = 400.dp)) {
                Text("Local Port: ${conn.localPort}", style = MaterialTheme.typography.bodyMedium)
                Text("Bytes Sent: ${conn.bytesSent} | Received: ${conn.bytesReceived}", style = MaterialTheme.typography.bodyMedium)
                Spacer(modifier = Modifier.height(8.dp))
                Text("Raw Stream / Payload:", style = MaterialTheme.typography.titleSmall)
                Spacer(modifier = Modifier.height(4.dp))
                Card(
                    modifier = Modifier.fillMaxWidth().weight(1f),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
                ) {
                    Box(modifier = Modifier.fillMaxSize().padding(8.dp)) {
                        Text(
                            text = conn.rawStreamPreview.ifBlank { "(No payload recorded)" },
                            fontFamily = FontFamily.Monospace,
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("Close") }
        }
    )
}
