package com.auth.reglog.service;

import com.auth.reglog.config.JwtConfig;
import com.auth.reglog.dto.request.*;
import com.auth.reglog.dto.response.*;
import com.auth.reglog.entity.*;
import com.auth.reglog.exception.*;
import com.auth.reglog.repository.*;
import com.auth.reglog.security.JwtTokenProvider;
import com.auth.reglog.security.UserPrincipal;
import com.auth.reglog.util.CookieUtil;
import com.auth.reglog.util.OtpUtil;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

/**
 * Core authentication service.
 * All business logic for registration, login, logout, password recovery,
 * session management, and password change.
 *
 * Business rules enforced here:
 * - Email normalized to lowercase
 * - Mobile number trimmed to digits only
 * - Passwords hashed with BCrypt; never stored as plaintext
 * - OTPs generated securely; only hash stored
 * - Reset tokens are opaque random values; only SHA-256 hash stored
 * - All password resets invalidate all active sessions
 */
@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;
    private final AuthSessionRepository authSessionRepository;
    private final PasswordRecoveryChallengeRepository challengeRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final JwtConfig jwtConfig;
    private final CookieUtil cookieUtil;
    private final EmailService emailService;

    @Value("${app.otp.expiry-minutes:5}")
    private int otpExpiryMinutes;

    @Value("${app.otp.max-attempts:5}")
    private int otpMaxAttempts;

    @Value("${app.otp.resend-cooldown-seconds:60}")
    private int otpResendCooldownSeconds;

    @Value("${app.reset-token.expiry-minutes:10}")
    private int resetTokenExpiryMinutes;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public AuthService(UserRepository userRepository,
                       AuthSessionRepository authSessionRepository,
                       PasswordRecoveryChallengeRepository challengeRepository,
                       PasswordEncoder passwordEncoder,
                       JwtTokenProvider jwtTokenProvider,
                       JwtConfig jwtConfig,
                       CookieUtil cookieUtil,
                       EmailService emailService) {
        this.userRepository = userRepository;
        this.authSessionRepository = authSessionRepository;
        this.challengeRepository = challengeRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
        this.jwtConfig = jwtConfig;
        this.cookieUtil = cookieUtil;
        this.emailService = emailService;
    }

    // ============================================================
    // REGISTRATION
    // ============================================================

    @Transactional
    public UserResponse register(RegisterRequest request) {
        String email = normalizeEmail(request.getEmail());
        String mobile = normalizeMobile(request.getMobileNumber());
        String fullName = request.getFullName().trim();

        // Check for existing user before attempting insert
        if (userRepository.existsByEmail(email)) {
            throw new DuplicateResourceException("An account with this email already exists");
        }
        if (userRepository.existsByMobileNumber(mobile)) {
            throw new DuplicateResourceException("An account with this mobile number already exists");
        }

        User user = User.builder()
                .fullName(fullName)
                .email(email)
                .mobileNumber(mobile)
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .active(true)
                .build();

        User saved = userRepository.save(user);
        log.info("New user registered: id={}", saved.getId());
        return toUserResponse(saved);
    }

    // ============================================================
    // LOGIN
    // ============================================================

    @Transactional
    public UserResponse login(LoginRequest request, HttpServletResponse response) {
        String identifier = request.getIdentifier().trim();
        Optional<User> userOpt = resolveUser(identifier);

        // Use constant-time comparison to avoid timing attacks regardless of outcome
        String candidateHash = userOpt.map(User::getPasswordHash).orElse("$2a$12$dummyhashfornouser000000000000000000000000000000000000000");
        boolean credentialsValid = userOpt.isPresent()
                && passwordEncoder.matches(request.getPassword(), candidateHash)
                && userOpt.get().isActive();

        if (!credentialsValid) {
            // Generic message — never reveal which field was wrong
            throw new AuthException("Invalid credentials");
        }

        User user = userOpt.get();
        String jti = JwtTokenProvider.generateJti();
        String token = jwtTokenProvider.generateToken(user.getId(), jti);
        Instant expiresAt = jwtTokenProvider.getExpiry();

        AuthSession session = AuthSession.builder()
                .user(user)
                .jti(jti)
                .expiresAt(expiresAt)
                .build();
        authSessionRepository.save(session);

        int maxAgeSecs = (int) (jwtConfig.getExpirationMs() / 1000);
        cookieUtil.addAuthCookie(response, token, maxAgeSecs);

        log.info("User logged in: id={}", user.getId());
        return toUserResponse(user);
    }

    // ============================================================
    // LOGOUT
    // ============================================================

    @Transactional
    public void logout(UserPrincipal principal, HttpServletResponse response) {
        int revoked = authSessionRepository.revokeByJti(principal.getJti(), Instant.now());
        if (revoked == 0) {
            log.warn("Logout called but session jti={} was already revoked or not found", principal.getJti());
        }
        cookieUtil.clearAuthCookie(response);
        log.info("User logged out: id={}", principal.getId());
    }

    // ============================================================
    // GET CURRENT USER
    // ============================================================

    public UserResponse getCurrentUser(UserPrincipal principal) {
        return userRepository.findById(principal.getId())
                .map(this::toUserResponse)
                .orElseThrow(() -> new AuthException("User not found"));
    }

    // ============================================================
    // FORGOT PASSWORD (send OTP)
    // ============================================================

    @Transactional
    public void forgotPassword(String identifier) {
        String normalizedIdentifier = identifier.trim();
        Optional<User> userOpt = resolveUser(normalizedIdentifier);

        // Always return after processing — do not reveal account existence
        if (userOpt.isEmpty()) {
            log.info("Forgot-password requested for unknown identifier (suppressing details)");
            return;
        }

        User user = userOpt.get();

        // Resend cooldown check
        List<PasswordRecoveryChallenge> recent =
                challengeRepository.findByUserIdOrderByCreatedAtDesc(user.getId());
        if (!recent.isEmpty()) {
            PasswordRecoveryChallenge last = recent.get(0);
            long secondsSinceLast = Duration.between(last.getCreatedAt(), Instant.now()).toSeconds();
            if (secondsSinceLast < otpResendCooldownSeconds) {
                log.info("OTP resend cooldown active for userId={}", user.getId());
                // Return generic response — do not reveal that cooldown is active
                return;
            }
        }

        // Invalidate any existing active challenges for this user
        challengeRepository.consumeAllForUser(user.getId(), Instant.now());

        String rawOtp = OtpUtil.generate();
        String otpHash = passwordEncoder.encode(rawOtp);
        Instant otpExpiry = Instant.now().plusSeconds(otpExpiryMinutes * 60L);

        PasswordRecoveryChallenge challenge = PasswordRecoveryChallenge.builder()
                .user(user)
                .otpHash(otpHash)
                .otpExpiresAt(otpExpiry)
                .attemptCount(0)
                .build();
        challengeRepository.save(challenge);

        // Send OTP email — if this fails, log at ERROR level but return generic success
        try {
            emailService.sendOtpEmail(user.getEmail(), user.getFullName(), rawOtp, otpExpiryMinutes);
            log.info("OTP email sent for userId={}", user.getId());
        } catch (Exception e) {
            // Log operational failure without exposing OTP or credentials
            log.error("Failed to send OTP email for userId={}: {}", user.getId(), e.getClass().getSimpleName());
            // Do NOT claim delivery succeeded if email failed; propagate as operational error
            throw new AuthException("Unable to send recovery email. Please try again later or contact support.");
        }
    }

    // ============================================================
    // VERIFY OTP
    // ============================================================

    @Transactional
    public VerifyOtpResponse verifyOtp(VerifyOtpRequest request) {
        String identifier = request.getIdentifier().trim();
        Optional<User> userOpt = resolveUser(identifier);

        if (userOpt.isEmpty()) {
            throw new AuthException("Invalid or expired OTP");
        }

        User user = userOpt.get();
        List<PasswordRecoveryChallenge> activeChallenges =
                challengeRepository.findActiveByUserId(user.getId(), Instant.now());

        if (activeChallenges.isEmpty()) {
            throw new AuthException("Invalid or expired OTP");
        }

        PasswordRecoveryChallenge challenge = activeChallenges.get(0);

        // Attempt limit check
        if (challenge.getAttemptCount() >= otpMaxAttempts) {
            challenge.setConsumedAt(Instant.now());
            challengeRepository.save(challenge);
            throw new AuthException("OTP attempt limit exceeded. Please request a new OTP.");
        }

        // OTP verification
        boolean otpMatches = passwordEncoder.matches(request.getOtp(), challenge.getOtpHash());
        if (!otpMatches) {
            challenge.setAttemptCount(challenge.getAttemptCount() + 1);
            if (challenge.getAttemptCount() >= otpMaxAttempts) {
                challenge.setConsumedAt(Instant.now());
                log.info("OTP challenge exhausted for userId={}", user.getId());
            }
            challengeRepository.save(challenge);
            throw new AuthException("Invalid or expired OTP");
        }

        // OTP verified — generate single-use reset token
        String rawResetToken = generateOpaqueToken();
        String tokenHash = sha256Hex(rawResetToken);
        Instant tokenExpiry = Instant.now().plusSeconds(resetTokenExpiryMinutes * 60L);

        challenge.setConsumedAt(Instant.now());
        challenge.setResetTokenHash(tokenHash);
        challenge.setResetTokenExpiresAt(tokenExpiry);
        challengeRepository.save(challenge);

        log.info("OTP verified, reset token issued for userId={}", user.getId());
        return VerifyOtpResponse.builder()
                .resetToken(rawResetToken)
                .expiresInSeconds(resetTokenExpiryMinutes * 60L)
                .build();
    }

    // ============================================================
    // RESET PASSWORD
    // ============================================================

    @Transactional
    public void resetPassword(ResetPasswordRequest request) {
        String tokenHash = sha256Hex(request.getResetToken());

        Optional<PasswordRecoveryChallenge> challengeOpt =
                challengeRepository.findByValidResetTokenHash(tokenHash, Instant.now());

        if (challengeOpt.isEmpty()) {
            throw new InvalidTokenException("Invalid, expired, or already-used reset token");
        }

        PasswordRecoveryChallenge challenge = challengeOpt.get();
        User user = challenge.getUser();

        // Update password
        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        // Mark reset token as used
        challenge.setResetTokenUsedAt(Instant.now());
        challengeRepository.save(challenge);

        // Revoke ALL active sessions for this user
        int revoked = authSessionRepository.revokeAllActiveSessionsForUser(user.getId(), Instant.now());
        log.info("Password reset completed for userId={}, {} sessions revoked", user.getId(), revoked);
    }

    // ============================================================
    // CHANGE PASSWORD (authenticated)
    // ============================================================

    @Transactional
    public void changePassword(UserPrincipal principal, ChangePasswordRequest request) {
        User user = userRepository.findById(principal.getId())
                .orElseThrow(() -> new AuthException("User not found"));

        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPasswordHash())) {
            throw new AuthException("Current password is incorrect");
        }

        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        // Revoke all sessions INCLUDING the current one for maximum security — user must re-login
        int revoked = authSessionRepository.revokeAllActiveSessionsForUser(user.getId(), Instant.now());
        log.info("Password changed for userId={}, {} sessions revoked (including current)", user.getId(), revoked);
    }

    // ============================================================
    // PRIVATE HELPERS
    // ============================================================

    private Optional<User> resolveUser(String identifier) {
        // 10 digits only = mobile number; otherwise treat as email
        if (identifier.matches("^\\d{10}$")) {
            return userRepository.findByMobileNumber(identifier);
        } else {
            return userRepository.findByEmail(normalizeEmail(identifier));
        }
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase();
    }

    private String normalizeMobile(String mobile) {
        return mobile.trim().replaceAll("[^0-9]", "");
    }

    private UserResponse toUserResponse(User user) {
        return UserResponse.builder()
                .id(user.getId())
                .fullName(user.getFullName())
                .email(user.getEmail())
                .mobileNumber(user.getMobileNumber())
                .build();
    }

    /**
     * Generate a 32-byte cryptographically random opaque token, Base64URL encoded.
     * Used for password reset tokens. Only the SHA-256 hash is stored.
     */
    private String generateOpaqueToken() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * SHA-256 hex digest — used to hash reset tokens for storage.
     * Not a password hash — use BCrypt for passwords.
     */
    private String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
