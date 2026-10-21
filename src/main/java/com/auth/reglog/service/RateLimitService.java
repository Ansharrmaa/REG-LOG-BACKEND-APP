package com.auth.reglog.service;

import com.auth.reglog.config.RateLimitConfig;
import com.auth.reglog.exception.RateLimitException;
import io.github.bucket4j.Bucket;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Enforces rate limits for login and forgot-password endpoints.
 * Keys are based on client IP address.
 *
 * In-memory implementation — not suitable for multi-instance deployments
 * without a shared backing store (e.g., Redis).
 */
@Service
public class RateLimitService {

    private final RateLimitConfig rateLimitConfig;
    private final ConcurrentHashMap<String, Bucket> loginBuckets;
    private final ConcurrentHashMap<String, Bucket> forgotPasswordBuckets;

    public RateLimitService(
            RateLimitConfig rateLimitConfig,
            @Qualifier("loginBuckets") ConcurrentHashMap<String, Bucket> loginBuckets,
            @Qualifier("forgotPasswordBuckets") ConcurrentHashMap<String, Bucket> forgotPasswordBuckets) {
        this.rateLimitConfig = rateLimitConfig;
        this.loginBuckets = loginBuckets;
        this.forgotPasswordBuckets = forgotPasswordBuckets;
    }

    public void checkLoginRateLimit(String clientIp) {
        Bucket bucket = loginBuckets.computeIfAbsent(
                clientIp, k -> rateLimitConfig.newLoginBucket()
        );
        if (!bucket.tryConsume(1)) {
            throw new RateLimitException("Too many login attempts. Please try again later.");
        }
    }

    public void checkForgotPasswordRateLimit(String clientIp) {
        Bucket bucket = forgotPasswordBuckets.computeIfAbsent(
                clientIp, k -> rateLimitConfig.newForgotPasswordBucket()
        );
        if (!bucket.tryConsume(1)) {
            throw new RateLimitException("Too many password reset requests. Please try again later.");
        }
    }
}
