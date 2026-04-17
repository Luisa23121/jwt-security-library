package co.edu.sena.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class JwtService {

    private final Key signingKey;
    private final long expirationMs;
    private final long refreshThresholdMs;
    private static final long MAX_REFRESH_WINDOW_MS = 24 * 60 * 60 * 1000; // 24h

    public JwtService(String base64Secret, long expirationMs, long refreshThresholdMs) {
        byte[] bytes = Base64.getDecoder().decode(base64Secret);
        this.signingKey = Keys.hmacShaKeyFor(bytes);
        this.expirationMs = expirationMs;
        this.refreshThresholdMs = refreshThresholdMs;
    }

    // Generar token con UUIDs
    public String generateToken(UUID userId, UUID rolId, String userName) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId.toString());
        claims.put("rolId", rolId.toString());

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userName)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(signingKey)
                .compact();
    }

    // Validar token
    public boolean isValidToken(String token) {
        try {
            getClaims(token);
            return true;
        } catch (JwtException e) {
            return false;
        }
    }

    // Obtener claims (lanza excepción si expiró o firma inválida)
    private Claims getClaims(String token) {
        return Jwts.parser()
                .setSigningKey(signingKey)
                .parseClaimsJws(token)
                .getBody();
    }

    // Extractores con UUID
    public String extractUserName(String token) {
        return getClaims(token).getSubject();
    }

    public UUID extractUserId(String token) {
        String id = getClaims(token).get("userId", String.class);
        return UUID.fromString(id);
    }

    public UUID extractRolId(String token) {
        String id = getClaims(token).get("rolId", String.class);
        return UUID.fromString(id);
    }

    public Date extractExpiration(String token) {
        return getClaims(token).getExpiration();
    }

    // Refresh: ¿debería renovar antes de expirar?
    public boolean shouldRefreshBeforeExpiry(String token) {
        try {
            long remaining = extractExpiration(token).getTime() - System.currentTimeMillis();
            return remaining < refreshThresholdMs;
        } catch (ExpiredJwtException e) {
            return true; // ya expiró, también necesita refresh
        } catch (JwtException e) {
            return false;
        }
    }

    // Renovar token (maneja tokens expirados recientemente)
    public String refreshToken(String token) {
        UUID userId;
        UUID rolId;
        String userName;

        try {
            // Caso normal: token aún vigente
            userId = extractUserId(token);
            rolId = extractRolId(token);
            userName = extractUserName(token);
        } catch (ExpiredJwtException e) {
            // Token expirado pero firma válida
            Claims claims = e.getClaims();
            userId = UUID.fromString(claims.get("userId", String.class));
            rolId = UUID.fromString(claims.get("rolId", String.class));
            userName = claims.getSubject();

            long expiredSinceMs = System.currentTimeMillis() - claims.getExpiration().getTime();
            if (expiredSinceMs > MAX_REFRESH_WINDOW_MS) {
                throw new RuntimeException("Token expirado hace más de 24 horas. Login requerido.");
            }
        } catch (JwtException e) {
            throw new RuntimeException("Token inválido. No se puede renovar.");
        }

        return generateToken(userId, rolId, userName);
    }

    // Utilidad para extraer token del header
    public String extractBearer(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            throw new RuntimeException("Authorization header inválido");
        }
        return authorizationHeader.substring(7);
    }
}