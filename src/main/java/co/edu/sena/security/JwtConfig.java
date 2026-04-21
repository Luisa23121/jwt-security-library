package co.edu.sena.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtConfig {

    @Value("${custom.security.secret}")
    private String secret;

    @Value("${custom.security.expiration-ms}")
    private long expiration;

    @Value("${custom.security.refresh-threshold-ms:60000}")
    private long refreshThreshold;

    @Bean
    public JwtService jwtService() {
        return new JwtService(secret, expiration, refreshThreshold);
    }
}