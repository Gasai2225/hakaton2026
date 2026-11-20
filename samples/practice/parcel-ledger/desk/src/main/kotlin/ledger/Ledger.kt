package ledger

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class Ledger

fun main(args: Array<String>) { runApplication<Ledger>(*args) }
