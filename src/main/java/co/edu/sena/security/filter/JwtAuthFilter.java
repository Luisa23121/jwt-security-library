package co.edu.sena.security.filter;

import co.edu.sena.security.config.SecurityProperties;
import co.edu.sena.security.context.AuthenticatedUser;
import co.edu.sena.security.context.SecurityContextHolder;
import co.edu.sena.security.exception.TokenException;
import co.edu.sena.security.service.JwtService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final SecurityProperties properties;

    public JwtAuthFilter(JwtService jwtService, SecurityProperties properties) {
        this.jwtService = jwtService;
        this.properties = properties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        try {
            System.out.println("=== FILTRO EJECUTÁNDOSE: " + request.getRequestURI());

            String authHeader = request.getHeader("Authorization");
            System.out.println("=== AUTHORIZATION HEADER: " + authHeader);

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                writeJsonError(response,
                        HttpServletResponse.SC_UNAUTHORIZED,
                        "missing_token",
                        "Se requiere autenticación. Incluya el header: Authorization: Bearer <token>");
                return;
            }

            String token = jwtService.extractBearer(authHeader);

            if (!jwtService.isValidToken(token)) {
                writeJsonError(response,
                        HttpServletResponse.SC_UNAUTHORIZED,
                        "token_invalid",
                        "Token inválido o expirado");
                return;
            }

            UUID userId = jwtService.extractUserId(token);
            String userName = jwtService.extractUserName(token);
            List<String> roles = jwtService.extractRoles(token);

            SecurityContextHolder.set(
                    new AuthenticatedUser(userId, userName, roles));

            filterChain.doFilter(request, response);

        } catch (ExpiredJwtException e) {
            writeJsonError(response,
                    HttpServletResponse.SC_UNAUTHORIZED,
                    "token_expired",
                    "El token ha expirado. Solicite uno nuevo en /auth/refresh");
        } catch (JwtException e) {
            writeJsonError(response,
                    HttpServletResponse.SC_UNAUTHORIZED,
                    "token_invalid",
                    "Token malformado o con firma inválida");
        } catch (TokenException e) {
            int status = switch (e.getErrorType()) {
                case FORBIDDEN -> HttpServletResponse.SC_FORBIDDEN;
                default -> HttpServletResponse.SC_UNAUTHORIZED;
            };
            writeJsonError(response, status,
                    e.getErrorType().name().toLowerCase(),
                    e.getMessage());
        } finally {
            SecurityContextHolder.clear();
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return properties.getPublicPaths()
                .stream()
                .anyMatch(path::startsWith);
    }

    private void writeJsonError(HttpServletResponse response,
                                int status,
                                String code,
                                String message) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(String.format(
                "{\"error\":\"%s\",\"message\":\"%s\",\"status\":%d}",
                code, message, status));
    }
}