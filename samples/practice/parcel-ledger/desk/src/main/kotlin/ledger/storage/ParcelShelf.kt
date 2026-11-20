package ledger.storage

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository

@Repository
class ParcelShelf(private val jdbc: JdbcTemplate) {
    fun lookup(number: Long) =
        jdbc.queryForMap("SELECT owner_id, district FROM parcels WHERE id = ?", number)

    fun owned(number: Long, owner: String) =
        jdbc.queryForMap("SELECT district FROM parcels WHERE id = ? AND owner_id = ?", number, owner)
}
