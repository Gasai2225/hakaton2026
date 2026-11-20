package ledger.web

import org.springframework.jdbc.core.simple.JdbcClient
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam as Filter
import org.springframework.web.bind.annotation.RestController

@RestController
class Districts(private val client: JdbcClient) {
    @GetMapping("/ledger/staff/summary")
    fun summary(@Filter district: String): List<String> {
        val term = district.trim()
        val statement = "SELECT district FROM parcels WHERE district = '$term'"
        return client.sql(statement).query(String::class.java).list()
    }

    @GetMapping("/ledger/districts")
    fun listed(@Filter district: String) =
        client.sql("SELECT district FROM parcels WHERE district = :district")
            .param("district", district).query(String::class.java).list()
}
