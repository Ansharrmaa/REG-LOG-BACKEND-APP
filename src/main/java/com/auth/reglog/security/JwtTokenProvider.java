package com.auth.reglog.security;

import com.auth.reglog.config.JwtConfig;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

/**
 * Handles JWT token generation, parsing, and validation.
 *
 * Signing algorithm: HS256 with a 256-bit+ key from environment.
 * Claims: sub (userId as string), jti (UUID), iat, exp, iss.
 *
 * Server-side revocation is enforced via the auth_sessions table
 * (checked in JwtAuthenticationFilter), not in this class.
 */
@Component
public class JwtTokenProvider {

    private static final Logger log = LoggerFactory.getLogger(JwtTokenProvider.class);

    private final JwtConfig jwtConfig;

    public JwtTokenProvider(JwtConfig jwtConfig) {
        this.jwtConfig = jwtConfig;
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = Base64.getDecoder().decode(jwtConfig.getSecret());
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Generate a new signed JWT for the given userId.
     *
     * @param userId   the user's database ID
     * @param jti      a pre-generated UUID (caller owns this so it can be persisted)
     * @return signed JWT string
     */
    public String generateToken(Long userId, String jti) {
        Instant now = Instant.now();
        Instant expiry = now.plusMillis(jwtConfig.getExpirationMs());

        return Jwts.builder()
                .subject(String.valueOf(userId))
                .id(jti)
                .issuer(jwtConfig.getIssuer())
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiry))
                .signWith(getSigningKey())
                .compact();
    }

    /**
     * Parse and validate the JWT. Returns the Claims if valid.
     * Throws a JwtException subtype if invalid, expired, or malformed.
     */
    public Claims parseToken(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .requireIssuer(jwtConfig.getIssuer())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /** Extract userId (subject) from a validated token string. */
    public Long getUserIdFromToken(String token) {
        return Long.parseLong(parseToken(token).getSubject());
    }

    /** Extract jti from a validated token string. */
    public String getJtiFromToken(String token) {
        return parseToken(token).getId();
    }

    public Instant getExpiryFromToken(String token) {
        return parseToken(token).getExpiration().toInstant();
    }

    public Instant getExpiry() {
        return Instant.now().plusMillis(jwtConfig.getExpirationMs());
    }

    /** Generate a fresh UUID suitable for use as jti. */
    public static String generateJti() {
        return UUID.randomUUID().toString();
    }
}
