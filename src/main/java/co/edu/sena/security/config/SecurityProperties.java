package co.edu.sena.security.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * Propiedades configurables por cada microservicio en su application.yml.
 *
 * custom:
 *   security:
 *     secret: "base64-encoded-secret"
 *     expiration-ms: 3600000
 *     refresh-threshold-ms: 300000
 *     public-paths:
 *       - /auth/
 *       - /actuator/health
 */
@ConfigurationProperties(prefix = "custom.security")
public class SecurityProperties {

    private String secret;
    private long expirationMs = 3_600_000L;        // 1 hora por defecto
    private long refreshThresholdMs = 300_000L;     // 5 minutos por defecto
    private List<String> publicPaths = new ArrayList<>(
            List.of("/actuator/health", "/actuator/info")
    );

    // Getters y Setters explícitos (sin Lombok para evitar dependencia en config)
    public String getSecret() { return secret; }
    public void setSecret(String secret) { this.secret = secret; }

    public long getExpirationMs() { return expirationMs; }
    public void setExpirationMs(long expirationMs) {
        this.expirationMs = expirationMs;
    }

    public long getRefreshThresholdMs() { return refreshThresholdMs; }
    public void setRefreshThresholdMs(long refreshThresholdMs) {
        this.refreshThresholdMs = refreshThresholdMs;
    }

    public List<String> getPublicPaths() { return publicPaths; }
    public void setPublicPaths(List<String> publicPaths) {
        this.publicPaths = publicPaths;
    }
}