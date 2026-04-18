package co.edu.sena.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtConfig {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private long expiration;

    @Value("${jwt.refresh-threshold:60000}")
    private long refreshThreshold;

    @Bean
    public JwtService jwtService() {
        return new JwtService(secret, expiration, refreshThreshold);
    }
}