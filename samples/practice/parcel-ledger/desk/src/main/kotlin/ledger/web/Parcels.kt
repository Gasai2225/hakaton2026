package ledger.web

import java.security.Principal
import ledger.storage.ParcelShelf as Shelf
import org.springframework.web.bind.annotation.*

@RestController
class Parcels(private val store: Shelf) {
    @GetMapping("/ledger/parcels/{number}")
    fun byNumber(@PathVariable number: Long) = store.lookup(number)

    @GetMapping("/ledger/mine/{number}")
    fun owned(@PathVariable number: Long, principal: Principal) = store.owned(number, principal.name)
}
