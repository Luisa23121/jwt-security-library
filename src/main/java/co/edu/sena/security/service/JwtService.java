package co.edu.sena.security.service;

import co.edu.sena.security.exception.TokenException;
import co.edu.sena.security.exception.TokenException.ErrorType;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Function;

public class JwtService {

    private static final int MIN_KEY_BYTES = 32;
    private static final long MAX_REFRESH_WINDOW_MS = 86_400_000L;

    private final SecretKey signingKey;
    private final long tokenExpirationMs;
    private final long refreshThresholdMs;

    public JwtService(String base64SecretKey,
                      long tokenExpirationMs,
                      long refreshThresholdMs) {

        Objects.requireNonNull(base64SecretKey, "jwt.secret no puede ser null");

        byte[] keyBytes;
        try {
            keyBytes = Base64.getDecoder().decode(base64SecretKey);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "jwt.secret no es Base64 válido. " +
                            "Genera uno con: openssl rand -base64 32", e);
        }

        if (keyBytes.length < MIN_KEY_BYTES) {
            throw new IllegalArgumentException(String.format(
                    "jwt.secret demasiado corto: mínimo %d bytes. " +
                            "Actual: %d bytes. Usa: openssl rand -base64 32",
                    MIN_KEY_BYTES, keyBytes.length));
        }

        this.signingKey = Keys.hmacShaKeyFor(keyBytes);
        this.tokenExpirationMs = tokenExpirationMs;
        this.refreshThresholdMs = refreshThresholdMs;
    }

    /* =========================================================
       GENERAR TOKEN
       Payload: { sub: email, userId: "uuid-string", roles: ["ADMINISTRADOR"] }
       ========================================================= */
    public String generateToken(UUID userId,        // UUID directo
                                String userName,
                                List<String> roles) {
        Objects.requireNonNull(userId, "userId no puede ser null");
        Objects.requireNonNull(userName, "userName no puede ser null");
        Objects.requireNonNull(roles, "roles no puede ser null");

        if (userName.isBlank())
            throw new IllegalArgumentException("userName no puede ser vacío");
        if (roles.isEmpty())
            throw new IllegalArgumentException(
                    "El usuario debe tener al menos un rol");

        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId.toString()); // UUID → String en el JWT
        claims.put("roles", roles);

        return Jwts.builder()
                .claims(claims)
                .subject(userName)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + tokenExpirationMs))
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
        } catch (ExpiredJwtException e) {
            return false;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    /* =========================================================
       PARSER CENTRAL
       ========================================================= */
    private Claims parse(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
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

    // Retorna UUID — convierte el String del token a UUID
    public UUID extractUserId(String token) {
        return extract(token, c -> {
            String id = c.get("userId", String.class);
            if (id == null) throw new TokenException(
                    "userId ausente en el token", ErrorType.INVALID_CLAIMS);
            try {
                return UUID.fromString(id);
            } catch (IllegalArgumentException e) {
                throw new TokenException(
                        "userId no es un UUID válido: " + id,
                        ErrorType.INVALID_CLAIMS);
            }
        });
    }

    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) {
        return extract(token, c -> {
            Object roles = c.get("roles");
            if (roles instanceof List<?>) return (List<String>) roles;
            throw new TokenException(
                    "roles inválidos en el token", ErrorType.INVALID_CLAIMS);
        });
    }

    public Date extractExpiration(String token) {
        return extract(token, Claims::getExpiration);
    }

    /* =========================================================
       REFRESH
       ========================================================= */
    public boolean shouldRefreshToken(String token) {
        try {
            long remaining = extractExpiration(token).getTime()
                    - System.currentTimeMillis();
            return remaining < refreshThresholdMs;
        } catch (ExpiredJwtException e) {
            return true;
        } catch (JwtException e) {
            return false;
        }
    }

    public String refreshToken(String token) {
        Claims claims;
        try {
            claims = parse(token);
        } catch (ExpiredJwtException e) {
            claims = e.getClaims();
            long expiredSinceMs = System.currentTimeMillis()
                    - claims.getExpiration().getTime();
            if (expiredSinceMs > MAX_REFRESH_WINDOW_MS) {
                throw new TokenException(
                        "Token expirado hace más de 24h, inicie sesión nuevamente",
                        ErrorType.REFRESH_DENIED);
            }
        } catch (JwtException e) {
            throw new TokenException(
                    "Firma inválida, refresh denegado",
                    ErrorType.INVALID_SIGNATURE, e);
        }

        String userIdStr = claims.get("userId", String.class);
        UUID userId;
        try {
            userId = UUID.fromString(userIdStr);
        } catch (IllegalArgumentException e) {
            throw new TokenException(
                    "userId no es un UUID válido en el token",
                    ErrorType.INVALID_CLAIMS);
        }

        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) claims.get("roles");

        return generateToken(userId, claims.getSubject(), roles);
    }

    /* =========================================================
       UTILIDAD HTTP
       ========================================================= */
    public String extractBearer(String authorizationHeader) {
        if (authorizationHeader == null)
            throw new TokenException("Header Authorization ausente",
                    ErrorType.MISSING_HEADER);
        if (!authorizationHeader.startsWith("Bearer "))
            throw new TokenException(
                    "Formato inválido: se espera 'Authorization: Bearer <token>'",
                    ErrorType.INVALID_FORMAT);
        String token = authorizationHeader.substring(7).trim();
        if (token.isBlank())
            throw new TokenException("El token no puede estar vacío",
                    ErrorType.INVALID_FORMAT);
        return token;
    }

    public long getExpirationMs() {
        return tokenExpirationMs;
    }
}