package co.edu.sena.security.context;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

/**
 * Representa al usuario autenticado en el contexto de la petición.
 * Contiene: id, nombre (subject del JWT) y lista de roles.
 * Se almacena en ThreadLocal durante el ciclo de vida de la petición.
 */
public record AuthenticatedUser(
        UUID userId,
        String userName,
        List<String> roles
) {

    /**
     * Verifica si el usuario tiene un rol específico (exacto).
     * Ej: hasRole("ADMINISTRADOR")
     */
    public boolean hasRole(String role) {
        if (roles == null || role == null) return false;
        return roles.contains(role.toUpperCase());
    }

    /**
     * Verifica si el usuario tiene AL MENOS UNO de los roles indicados.
     * Ej: hasAnyRole("ADMINISTRADOR", "INSTRUCTOR")
     */
    public boolean hasAnyRole(String... requiredRoles) {
        if (roles == null || requiredRoles == null) return false;
        return Arrays.stream(requiredRoles)
                .anyMatch(r -> roles.contains(r.toUpperCase()));
    }

    /**
     * Verifica si el usuario tiene TODOS los roles indicados.
     */
    public boolean hasAllRoles(String... requiredRoles) {
        if (roles == null || requiredRoles == null) return false;
        return Arrays.stream(requiredRoles)
                .allMatch(r -> roles.contains(r.toUpperCase()));
    }
}
