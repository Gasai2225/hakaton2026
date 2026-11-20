package ledger.dispatch

import javax.net.ssl.HttpsURLConnection

class Carrier {
    fun legacy(channel: HttpsURLConnection) {
        channel.setHostnameVerifier { _, _ -> true }
    }

    fun standard(channel: HttpsURLConnection) {
        channel.hostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier()
    }
}
