package practice.rooms

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.jdbc.core.simple.JdbcClient
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@SpringBootApplication
class ReadingRoom {
    val separatorToken = System.getProperty("room.separator") ?: " "
}

fun main(args: Array<String>) { runApplication<ReadingRoom>(*args) }

@RestController
class Rooms(private val db: JdbcClient) {
    @GetMapping("/rooms")
    fun names(@RequestParam floor: String): List<String> =
        db.sql("SELECT name FROM rooms WHERE floor = :floor")
            .param("floor", floor).query(String::class.java).list()
}
