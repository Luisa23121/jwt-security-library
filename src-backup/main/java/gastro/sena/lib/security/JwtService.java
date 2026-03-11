package gastro.sena.lib.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

public class JwtService {

    private final Key signingKey;
    private final long tokenExpirationMs;
    private final long refreshThresholdMs;

    public JwtService(String base64SecretKey, long tokenExpirationMs, long refreshThresholdMs) {
        byte[] keyBytes = Base64.getDecoder().decode(base64SecretKey);
        this.signingKey = Keys.hmacShaKeyFor(keyBytes);

        this.tokenExpirationMs = tokenExpirationMs;
        this.refreshThresholdMs = refreshThresholdMs;
    }

    /* =========================================================
       GENERAR TOKEN
       ========================================================= */
    public String generateToken(Long userId, Long rolId, String userName) {

        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("rolId", rolId);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userName)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + tokenExpirationMs))
                .signWith(signingKey)
                .compact();
    }

    /* =========================================================
       VALIDACIÓN
       ========================================================= */
    public boolean isValidToken(String token) {
        try {
            parse(token);
            return true;
        } catch (JwtException e) {
            return false;
        }
    }

    /* =========================================================
       PARSER CENTRAL (reutilizable)
       ========================================================= */
    private Claims parse(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private <T> T extract(String token, Function<Claims, T> resolver) {
        return resolver.apply(parse(token));
    }

    /* =========================================================
       EXTRACCIÓN DE DATOS
       ========================================================= */
    public String extractUserName(String token) {
        return extract(token, Claims::getSubject);
    }

    public Long extractUserId(String token) {
        return extract(token, c -> c.get("userId", Long.class));
    }

    public Long extractRolId(String token) {
        return extract(token, c -> c.get("rolId", Long.class));
    }

    public Date extractExpiration(String token) {
        return extract(token, Claims::getExpiration);
    }

    /* =========================================================
       REFRESH
       ========================================================= */
    public boolean shouldRefreshToken(String token) {
        long remaining = extractExpiration(token).getTime() - System.currentTimeMillis();
        return remaining < refreshThresholdMs;
    }

    public String refreshToken(String token) {
        if (!isValidToken(token)) {
            throw new RuntimeException("Token inválido o expirado");
        }

        return generateToken(
                extractUserId(token),
                extractRolId(token),
                extractUserName(token)
        );
    }

    /* =========================================================
       UTILIDAD PARA HTTP (Bearer)
       ========================================================= */
    public String extractBearer(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            throw new RuntimeException("Authorization header inválido");
        }
        return authorizationHeader.substring(7);
    }

    public long getExpirationMs() {
        return tokenExpirationMs;
    }
}