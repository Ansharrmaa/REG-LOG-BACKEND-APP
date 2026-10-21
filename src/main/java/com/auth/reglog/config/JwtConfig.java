package com.auth.reglog.config;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * JWT configuration bean. Reads secrets from environment/properties only.
 * Fails fast at startup if JWT_SECRET is absent or too short.
 */
@Component
public class JwtConfig {

    @Value("${app.jwt.secret}")
    private String secret;

    @Value("${app.jwt.expiration-ms}")
    private long expirationMs;

    @Value("${app.jwt.issuer}")
    private String issuer;

    @Value("${app.jwt.cookie-name}")
    private String cookieName;

    @Value("${app.jwt.cookie-secure}")
    private boolean cookieSecure;

    @PostConstruct
    public void validate() {
        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException(
                "JWT_SECRET environment variable is not set. " +
                "A strong secret is required. See .env.example for setup instructions."
            );
        }
        // Base64-decoded secret must be at least 32 bytes (256 bits) for HS256
        byte[] decoded;
        try {
            decoded = java.util.Base64.getDecoder().decode(secret);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(
                "JWT_SECRET must be a valid Base64-encoded string. " +
                "Generate one with: openssl rand -base64 32"
            );
        }
        if (decoded.length < 32) {
            throw new IllegalStateException(
                "JWT_SECRET is too short. Must decode to at least 256 bits (32 bytes). " +
                "Generate a strong secret with: openssl rand -base64 32"
            );
        }
    }

    public String getSecret() {
        return secret;
    }

    public long getExpirationMs() {
        return expirationMs;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getCookieName() {
        return cookieName;
    }

    public boolean isCookieSecure() {
        return cookieSecure;
    }
}
