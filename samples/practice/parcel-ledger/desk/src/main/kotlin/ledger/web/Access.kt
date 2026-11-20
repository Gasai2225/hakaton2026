package ledger.web

import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod.GET
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

@Configuration
@ConditionalOnWebApplication
class Access {
    @Bean
    fun registry(http: HttpSecurity): SecurityFilterChain = http
        .cors { it.configurationSource(origins()) }
        .authorizeHttpRequests { routes ->
            routes.requestMatchers(GET, "/ledger/about").permitAll()
            routes.requestMatchers(GET, "/ledger/staff/summary").permitAll()
            routes.requestMatchers("/ledger/staff/**").hasRole("DISPATCH")
            routes.anyRequest().authenticated()
        }.build()

    @Bean
    fun origins(): UrlBasedCorsConfigurationSource {
        val manifests = CorsConfiguration().also { cfg ->
            cfg.allowCredentials = true
            cfg.addAllowedOriginPattern("*")
        }
        val tracking = CorsConfiguration().apply {
            allowCredentials = true
            allowedOriginPatterns = listOf("https://training.example")
        }
        return UrlBasedCorsConfigurationSource().apply {
            registerCorsConfiguration("/ledger/staff/**", manifests)
            registerCorsConfiguration("/ledger/mine/**", tracking)
        }
    }
}
