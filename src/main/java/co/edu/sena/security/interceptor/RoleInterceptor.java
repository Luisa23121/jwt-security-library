package co.edu.sena.security.interceptor;

import java.util.Arrays;
import co.edu.sena.security.annotacion.RequireRole;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class RoleInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response,
                             Object handler) throws Exception {

        if (!(handler instanceof HandlerMethod method)) return true;

        RequireRole annotation = method.getMethodAnnotation(RequireRole.class);
        if (annotation == null) {
            annotation = method.getBeanType().getAnnotation(RequireRole.class);
        }
        if (annotation == null) return true;

        // Lee el nombre del rol que guardó la librería
        Object rol = request.getAttribute("nombreRol");
        System.out.println(">>> nombreRol: " + rol);

        if (!(rol instanceof String nombreRol)) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter()
                    .write("{\"error\": \"Usuario no autenticado con rol\"}");
            return false;
        }

        // Compara por nombre del enum
        boolean hasRole = Arrays.stream(annotation.value())
                .anyMatch(role -> role.name().equals(nombreRol));

        if (!hasRole) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.getWriter()
                    .write("{\"error\": \"No tienes permisos para realizar esta acción\"}");
            return false;
        }

        return true;
    }
}
