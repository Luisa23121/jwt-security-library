package co.edu.sena.security.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Requiere que el usuario tenga TODOS los roles especificados.
 * Se puede aplicar a nivel de clase o método.
 *
 * Uso:
 *   @RequiereRol("ADMINISTRADOR")
 *   @RequiereRol({"ADMINISTRADOR", "INSTRUCTOR"})
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequiereRol {
    String[] value();
}