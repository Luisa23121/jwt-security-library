package co.edu.sena.security.interceptor;

import co.edu.sena.security.annotation.RequiereCualquierRol;
import co.edu.sena.security.annotation.RequiereRol;
import co.edu.sena.security.context.AuthenticatedUser;
import co.edu.sena.security.context.SecurityContextHolder;
import co.edu.sena.security.exception.TokenException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import java.io.IOException;
import java.lang.annotation.Annotation;
import java.util.Arrays;

/**
 * Interceptor que procesa las anotaciones @RequiereRol y @RequiereCualquierRol.
 * Se ejecuta DESPUÉS del JwtAuthFilter.
 *
 * Prioridad: anotación en método > anotación en clase.
 *
 * Este interceptor NO se registra automáticamente.
 * Cada microservicio lo registra en su WebMvcConfigurer.
 */
public class RoleEnforcementInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response,
                             Object handler) throws Exception {

        // Solo procesar HandlerMethod (controllers), no recursos estáticos
        if (!(handler instanceof HandlerMethod method)) {
            return true;
        }

        // Verificar @RequiereRol (TODOS los roles son requeridos)
        RequiereRol requiereRol = getAnnotation(method, RequiereRol.class);
        if (requiereRol != null) {
            AuthenticatedUser user = resolveUser(response);
            if (user == null) return false;

            boolean tienesTodos = Arrays.stream(requiereRol.value())
                    .allMatch(user::hasRole);

            if (!tienesTodos) {
                return writeForbidden(response,
                        "Acceso denegado. Roles requeridos: "
                                + Arrays.toString(requiereRol.value()));
            }
        }

        // Verificar @RequiereCualquierRol (AL MENOS UN rol)
        RequiereCualquierRol cualquierRol =
                getAnnotation(method, RequiereCualquierRol.class);
        if (cualquierRol != null) {
            AuthenticatedUser user = resolveUser(response);
            if (user == null) return false;

            boolean tieneAlguno = user.hasAnyRole(cualquierRol.value());
            if (!tieneAlguno) {
                return writeForbidden(response,
                        "Acceso denegado. Se requiere uno de: "
                                + Arrays.toString(cualquierRol.value()));
            }
        }

        return true;
    }

    /**
     * Busca la anotación primero en el método, luego en la clase.
     */
    private <A extends Annotation> A getAnnotation(HandlerMethod method,
                                                   Class<A> type) {
        A annotation = method.getMethodAnnotation(type);
        if (annotation != null) return annotation;
        return method.getBeanType().getAnnotation(type);
    }

    /**
     * Obtiene el usuario autenticado o escribe 401 si no está autenticado.
     */
    private AuthenticatedUser resolveUser(HttpServletResponse response)
            throws IOException {
        try {
            return SecurityContextHolder.get();
        } catch (TokenException e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(
                    "{\"error\":\"unauthorized\"," +
                            "\"message\":\"Debe iniciar sesión para acceder a este recurso\"," +
                            "\"status\":401}");
            return null;
        }
    }

    private boolean writeForbidden(HttpServletResponse response,
                                   String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(String.format(
                "{\"error\":\"forbidden\",\"message\":\"%s\",\"status\":403}",
                message));
        return false;
    }
}
