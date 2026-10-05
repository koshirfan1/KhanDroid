package com.khandroid.app.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.khandroid.app.data.HttpExchangeEntity
import com.khandroid.app.data.HttpExchangeDao
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SessionsScreen(dao: HttpExchangeDao) {
    val exchanges by dao.observeAll().collectAsState(initial = emptyList())
    var selected by remember { mutableStateOf<HttpExchangeEntity?>(null) }
    val scope = rememberCoroutineScope()

    if (selected != null) {
        ExchangeDetailScreen(selected!!) { selected = null }
        return
    }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text("Sessions (${exchanges.size})", style = MaterialTheme.typography.headlineSmall)
            TextButton(onClick = { scope.launch { dao.clearAll() } }) { Text("Clear") }
        }

        Spacer(Modifier.height(8.dp))

        if (exchanges.isEmpty()) {
            Text(
                "No HTTP exchanges captured yet. Start a capture with HTTP inspection " +
                    "enabled and generate some traffic in the target app.",
                style = MaterialTheme.typography.bodyMedium
            )
            return@Column
        }

        LazyColumn {
            items(exchanges, key = { it.id }) { ex ->
                Surface(onClick = { selected = ex }, modifier = Modifier.fillMaxWidth()) {
                    ListItem(
                        headlineContent = { Text("${ex.method} ${ex.host}${ex.path}") },
                        supportingContent = {
                            Text(
                                "${if (ex.isTls) "https" else "http"} \u00b7 ${ex.statusCode ?: "?"} \u00b7 " +
                                    "${ex.durationMs}ms" + (ex.decryptedWith?.let { " \u00b7 decrypted: $it" } ?: "") +
                                    (ex.error?.let { " \u00b7 error: $it" } ?: "")
                            )
                        }
                    )
                }
                HorizontalDivider()
            }
        }
    }
}

@Composable
private fun ExchangeDetailScreen(ex: HttpExchangeEntity, onBack: () -> Unit) {
    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        TextButton(onClick = onBack) { Text("\u2190 Back") }
        Text("${ex.method} ${ex.host}${ex.path}", style = MaterialTheme.typography.titleMedium)
        Text(
            "${if (ex.isTls) "HTTPS" else "HTTP"} \u00b7 status ${ex.statusCode ?: "?"} \u00b7 ${ex.durationMs}ms",
            style = MaterialTheme.typography.bodySmall
        )
        ex.decryptedWith?.let { Text("Decrypted with: $it", style = MaterialTheme.typography.bodySmall) }
        ex.error?.let { Text("Error: $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }

        Spacer(Modifier.height(12.dp))
        LazyColumn {
            item { SectionLabel("Request headers"); MonoBlock(ex.reqHeadersBlock) }
            item { SectionLabel("Request body"); MonoBlock(ex.reqBodyPreview ?: "(empty)") }
            item { SectionLabel("Response headers"); MonoBlock(ex.resHeadersBlock) }
            item { SectionLabel("Response body"); MonoBlock(ex.resBodyPreview ?: "(empty)") }
        }
    }
}

@Composable
private fun SectionLabel(text: String) {
    Text(text, style = MaterialTheme.typography.labelLarge, modifier = Modifier.padding(top = 12.dp, bottom = 4.dp))
}

@Composable
private fun MonoBlock(text: String) {
    Text(text, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
}
