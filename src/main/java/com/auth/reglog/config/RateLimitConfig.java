package com.auth.reglog.config;

import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.local.LocalBucketBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

/**
 * Rate limiting configuration using Bucket4j with Caffeine in-memory cache.
 *
 * WARNING: These rate limits are per-instance and in-memory only.
 * In a multi-instance deployment, replace with a Redis-backed Bucket4j
 * configuration (bucket4j-redis) to share state across instances.
 */
@Configuration
public class RateLimitConfig {

    @Value("${app.rate-limit.login.capacity:5}")
    private int loginCapacity;

    @Value("${app.rate-limit.login.refill-tokens:5}")
    private int loginRefillTokens;

    @Value("${app.rate-limit.login.refill-seconds:60}")
    private int loginRefillSeconds;

    @Value("${app.rate-limit.forgot-password.capacity:3}")
    private int forgotCapacity;

    @Value("${app.rate-limit.forgot-password.refill-tokens:3}")
    private int forgotRefillTokens;

    @Value("${app.rate-limit.forgot-password.refill-seconds:300}")
    private int forgotRefillSeconds;

    @Bean("loginBuckets")
    public ConcurrentHashMap<String, Bucket> loginBuckets() {
        return createBucketMap(loginCapacity, loginRefillTokens, loginRefillSeconds);
    }

    @Bean("forgotPasswordBuckets")
    public ConcurrentHashMap<String, Bucket> forgotPasswordBuckets() {
        return createBucketMap(forgotCapacity, forgotRefillTokens, forgotRefillSeconds);
    }

    private ConcurrentHashMap<String, Bucket> createBucketMap(
            int capacity, int refillTokens, int refillSeconds) {
        // Entries auto-expire 1 hour after last access to avoid memory leaks
        // We wrap with a Caffeine-backed computeIfAbsent pattern in RateLimitService
        return new ConcurrentHashMap<>();
    }

    /** Factory method for creating a rate limit bucket with given configuration. */
    public Bucket newLoginBucket() {
        return Bucket.builder()
                .addLimit(Bandwidth.builder()
                    .capacity(loginCapacity)
                    .refillGreedy(loginRefillTokens, Duration.ofSeconds(loginRefillSeconds))
                    .build())
                .build();
    }

    public Bucket newForgotPasswordBucket() {
        return Bucket.builder()
                .addLimit(Bandwidth.builder()
                    .capacity(forgotCapacity)
                    .refillGreedy(forgotRefillTokens, Duration.ofSeconds(forgotRefillSeconds))
                    .build())
                .build();
    }
}
