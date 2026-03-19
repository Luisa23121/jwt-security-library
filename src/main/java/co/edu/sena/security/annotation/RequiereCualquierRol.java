package co.edu.sena.security.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Requiere que el usuario tenga AL MENOS UNO de los roles especificados.
 * Se puede aplicar a nivel de clase o método.
 *
 * Uso:
 *   @RequiereCualquierRol({"ADMINISTRADOR", "INSTRUCTOR"})
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequiereCualquierRol {
    String[] value();
}