package com.auth.reglog.util;

import java.security.SecureRandom;

/**
 * Utility for generating cryptographically secure 6-digit OTPs.
 */
public final class OtpUtil {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private OtpUtil() {}

    /**
     * Generate a cryptographically secure 6-digit numeric OTP.
     * Output is zero-padded to always be exactly 6 characters.
     *
     * @return string like "042718"
     */
    public static String generate() {
        int otp = SECURE_RANDOM.nextInt(1_000_000); // 0 to 999999
        return String.format("%06d", otp);
    }
}
