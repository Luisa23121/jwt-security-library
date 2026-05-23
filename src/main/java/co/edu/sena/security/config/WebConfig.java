package co.edu.sena.security.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import co.edu.sena.security.interceptor.RoleInterceptor;

import lombok.RequiredArgsConstructor;

// Configuracion para registrar interceptores en spring
@RequiredArgsConstructor
@Configuration
public class WebConfig implements WebMvcConfigurer{
    private final RoleInterceptor rolInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // Registramos el interceptor para que se ejecute en todas las rutas
        registry.addInterceptor(rolInterceptor);
    }
}