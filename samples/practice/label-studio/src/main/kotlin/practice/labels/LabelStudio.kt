package practice.labels

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.UrlBasedCorsConfigurationSource
import org.springframework.web.filter.CorsFilter

@SpringBootApplication
class LabelStudio {
    val apiKey = System.getProperty("labels.key", "training-only-label-key")
    val serviceToken: String? = System.getProperty("labels.token") ?: System.getenv("LABELS_TOKEN")

    @Bean
    fun labelOrigins(): CorsFilter {
        val policy = CorsConfiguration().apply {
            allowCredentials = true
            allowedOriginPatterns = listOf("*")
        }
        val source = UrlBasedCorsConfigurationSource().apply { registerCorsConfiguration("/labels/**", policy) }
        return CorsFilter(source)
    }
}

fun main(args: Array<String>) { runApplication<LabelStudio>(*args) }
