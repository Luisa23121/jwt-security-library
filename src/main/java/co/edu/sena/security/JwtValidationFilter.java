package co.edu.sena.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.UUID;

@Component
public class JwtValidationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtService jwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {

        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7);

        try {
            String tokenFinal = token;

            // Si debería refrescar antes o ya expiró
            if (jwtService.shouldRefreshBeforeExpiry(token) || !jwtService.isValidToken(token)) {
                tokenFinal = jwtService.refreshToken(token);
                response.setHeader("Authorization", "Bearer " + tokenFinal);
            }

            // Extraer datos
            UUID userId = jwtService.extractUserId(tokenFinal);
            String userName = jwtService.extractUserName(tokenFinal);
            String rolId = jwtService.extractRolId(tokenFinal);

            // Guardar en request
            request.setAttribute("userId", userId);
            request.setAttribute("userName", userName);
            request.setAttribute("rolId", rolId);

            chain.doFilter(request, response);

        } catch (RuntimeException e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"" + e.getMessage() + "\"}");
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.equals("/login") || path.equals("/register") || path.startsWith("/auth/");
    }
}