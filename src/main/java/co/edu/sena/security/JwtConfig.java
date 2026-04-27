package co.edu.sena.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtConfig {

    @Value("${security.secret}")
    private String secret;

    @Value("${security.expiration-ms}")
    private long expiration;

    @Value("${security.refresh-threshold-ms:60000}")
    private long refreshThreshold;

    @Bean
    public JwtService jwtService() {
        return new JwtService(secret, expiration, refreshThreshold);
    }
}