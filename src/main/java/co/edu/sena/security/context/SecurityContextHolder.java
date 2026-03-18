package co.edu.sena.security.context;

import co.edu.sena.security.exception.TokenException;
import co.edu.sena.security.exception.TokenException.ErrorType;

/**
 * Almacena el usuario autenticado en un ThreadLocal.
 * IMPORTANTE: clear() DEBE llamarse en el finally del filtro
 * para evitar memory leaks en servidores con thread pools.
 */
public final class SecurityContextHolder {

    private static final ThreadLocal<AuthenticatedUser> CONTEXT =
            new ThreadLocal<>();

    private SecurityContextHolder() {}

    public static void set(AuthenticatedUser user) {
        CONTEXT.set(user);
    }

    /**
     * Retorna el usuario autenticado.
     * Lanza TokenException si no hay usuario en el contexto.
     */
    public static AuthenticatedUser get() {
        AuthenticatedUser user = CONTEXT.get();
        if (user == null) {
            throw new TokenException(
                    "No hay usuario autenticado en el contexto actual",
                    ErrorType.UNAUTHORIZED
            );
        }
        return user;
    }

    /**
     * Retorna null si no hay usuario autenticado (sin lanzar excepción).
     * Útil para endpoints que pueden ser públicos o privados.
     */
    public static AuthenticatedUser getOrNull() {
        return CONTEXT.get();
    }

    public static boolean isAuthenticated() {
        return CONTEXT.get() != null;
    }

    /**
     * Limpia el contexto. SIEMPRE llamar en el bloque finally del filtro.
     */
    public static void clear() {
        CONTEXT.remove();
    }
}
