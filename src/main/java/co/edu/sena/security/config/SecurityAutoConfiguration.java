package co.edu.sena.security.config;

import co.edu.sena.security.filter.JwtAuthFilter;
import co.edu.sena.security.interceptor.RoleEnforcementInterceptor;
import co.edu.sena.security.service.JwtService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

/**
 * AutoConfiguration principal de la librería.
 *
 * Expone los beans disponibles pero NO los registra automáticamente
 * en ningún filtro o interceptor. Cada microservicio decide cómo y
 * dónde aplicarlos en su propio SecurityConfig.
 *
 * Para deshabilitar completamente la librería:
 *   custom.security.enabled=false
 */
@AutoConfiguration
@ConditionalOnProperty(
        prefix = "custom.security",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
)
@EnableConfigurationProperties(SecurityProperties.class)
@Import(JwtConfig.class)
public class SecurityAutoConfiguration {

    /**
     * Filtro JWT disponible para que el microservicio lo registre.
     * NO se registra automáticamente como FilterRegistrationBean.
     */
    @Bean
    @ConditionalOnMissingBean
    public JwtAuthFilter jwtAuthFilter(JwtService jwtService,
                                       SecurityProperties properties) {
        return new JwtAuthFilter(jwtService, properties);
    }

    /**
     * Interceptor de roles disponible para que el microservicio lo registre.
     * NO se registra automáticamente en WebMvcConfigurer.
     */
    @Bean
    @ConditionalOnMissingBean
    public RoleEnforcementInterceptor roleEnforcementInterceptor() {
        return new RoleEnforcementInterceptor();
    }
}
