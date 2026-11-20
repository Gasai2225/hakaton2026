package practice.books

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.jdbc.core.simple.JdbcClient as CatalogClient
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@SpringBootApplication
class BookIndex

fun main(args: Array<String>) { runApplication<BookIndex>(*args) }

@RestController
class Books(private val db: CatalogClient) {
    @GetMapping("/books")
    fun titles(@RequestParam shelf: String): List<String> {
        val statement = "SELECT title FROM books WHERE shelf = '$shelf'"
        return db.sql(statement).query(String::class.java).list()
    }
}
