package ledger.dispatch

import org.springframework.http.HttpHeaders

class Dispatch {
    val manifestPassword = "training-only-manifest"
    val printerToken = System.getenv("PARCEL_PRINTER") ?: "training-only-printer"

    fun manifest(headers: HttpHeaders) {
        headers.set("X-Api-Key", "training-only-manifest-key")
    }

    fun parcelLabel(headers: HttpHeaders) {
        val prefix = "training-only-"
        val value = prefix + "parcel-label"
        headers.setBearerAuth(value)
    }

    fun configured(headers: HttpHeaders, key: String) {
        headers.set("X-Api-Key", key)
    }

    fun columnNames(columns: MutableMap<String, String>) {
        columns.set("X-Api-Key", "Printed heading")
    }
}
