package co.edu.sena.security.exception;

public class TokenException extends RuntimeException {

    public enum ErrorType {
        MISSING_HEADER,
        INVALID_FORMAT,
        EXPIRED,
        INVALID_SIGNATURE,
        INVALID_CLAIMS,
        REFRESH_DENIED,
        FORBIDDEN,
        UNAUTHORIZED
    }

    private final ErrorType errorType;

    public TokenException(String message, ErrorType errorType) {
        super(message);
        this.errorType = errorType;
    }

    public TokenException(String message, ErrorType errorType, Throwable cause) {
        super(message, cause);
        this.errorType = errorType;
    }

    public ErrorType getErrorType() {
        return errorType;
    }
}
