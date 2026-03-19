package co.edu.sena.security.config;

import co.edu.sena.security.service.JwtService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(SecurityProperties.class)
public class JwtConfig {

    @Bean
    @ConditionalOnMissingBean
    public JwtService jwtService(SecurityProperties properties) {
        if (properties.getSecret() == null || properties.getSecret().isBlank()) {
            throw new IllegalStateException(
                    "custom.security.secret es obligatorio. " +
                            "Genera uno con: openssl rand -base64 32");
        }
        return new JwtService(
                properties.getSecret(),
                properties.getExpirationMs(),
                properties.getRefreshThresholdMs()
        );
    }
}
