package com.auth.reglog.service;

import com.auth.reglog.config.JwtConfig;
import com.auth.reglog.dto.request.*;
import com.auth.reglog.dto.response.UserResponse;
import com.auth.reglog.dto.response.VerifyOtpResponse;
import com.auth.reglog.entity.*;
import com.auth.reglog.exception.*;
import com.auth.reglog.repository.*;
import com.auth.reglog.security.JwtTokenProvider;
import com.auth.reglog.security.UserPrincipal;
import com.auth.reglog.util.CookieUtil;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for AuthService.
 * All dependencies are mocked. No database or SMTP required.
 */
@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private AuthSessionRepository authSessionRepository;
    @Mock private PasswordRecoveryChallengeRepository challengeRepository;
    @Mock private JwtTokenProvider jwtTokenProvider;
    @Mock private JwtConfig jwtConfig;
    @Mock private CookieUtil cookieUtil;
    @Mock private EmailService emailService;
    @Mock private HttpServletResponse httpServletResponse;

    @InjectMocks
    private AuthService authService;

    private final PasswordEncoder realPasswordEncoder = new BCryptPasswordEncoder(4); // Low cost for tests

    @BeforeEach
    void setUp() {
        // Inject real password encoder
        ReflectionTestUtils.setField(authService, "passwordEncoder", realPasswordEncoder);
        ReflectionTestUtils.setField(authService, "otpExpiryMinutes", 5);
        ReflectionTestUtils.setField(authService, "otpMaxAttempts", 5);
        ReflectionTestUtils.setField(authService, "otpResendCooldownSeconds", 60);
        ReflectionTestUtils.setField(authService, "resetTokenExpiryMinutes", 10);
    }

    // ============================================================
    // REGISTRATION TESTS
    // ============================================================

    @Test
    @DisplayName("Successful registration returns user response")
    void register_success() {
        RegisterRequest req = new RegisterRequest();
        req.setFullName("  Test User  ");
        req.setEmail("USER@EXAMPLE.COM");
        req.setMobileNumber("9876543210");
        req.setPassword("Test@1234");
        req.setConfirmPassword("Test@1234");

        when(userRepository.existsByEmail("user@example.com")).thenReturn(false);
        when(userRepository.existsByMobileNumber("9876543210")).thenReturn(false);

        User savedUser = User.builder()
                .id(1L)
                .fullName("Test User")
                .email("user@example.com")
                .mobileNumber("9876543210")
                .passwordHash(realPasswordEncoder.encode("Test@1234"))
                .build();
        when(userRepository.save(any(User.class))).thenReturn(savedUser);

        UserResponse response = authService.register(req);

        assertThat(response.getEmail()).isEqualTo("user@example.com");
        assertThat(response.getFullName()).isEqualTo("Test User");
        assertThat(response.getMobileNumber()).isEqualTo("9876543210");
        verify(userRepository).save(argThat(u ->
            u.getEmail().equals("user@example.com") &&
            !u.getPasswordHash().equals("Test@1234") // must be hashed
        ));
    }

    @Test
    @DisplayName("Registration fails on duplicate email")
    void register_duplicateEmail_throwsConflict() {
        RegisterRequest req = new RegisterRequest();
        req.setFullName("Test User");
        req.setEmail("existing@example.com");
        req.setMobileNumber("9876543210");
        req.setPassword("Test@1234");
        req.setConfirmPassword("Test@1234");

        when(userRepository.existsByEmail("existing@example.com")).thenReturn(true);

        assertThatThrownBy(() -> authService.register(req))
                .isInstanceOf(DuplicateResourceException.class)
                .hasMessageContaining("email");
    }

    @Test
    @DisplayName("Registration fails on duplicate mobile number")
    void register_duplicateMobile_throwsConflict() {
        RegisterRequest req = new RegisterRequest();
        req.setFullName("Test User");
        req.setEmail("newuser@example.com");
        req.setMobileNumber("9876543210");
        req.setPassword("Test@1234");
        req.setConfirmPassword("Test@1234");

        when(userRepository.existsByEmail("newuser@example.com")).thenReturn(false);
        when(userRepository.existsByMobileNumber("9876543210")).thenReturn(true);

        assertThatThrownBy(() -> authService.register(req))
                .isInstanceOf(DuplicateResourceException.class)
                .hasMessageContaining("mobile");
    }

    @Test
    @DisplayName("Email is normalized to lowercase on registration")
    void register_normalizesEmailToLowercase() {
        RegisterRequest req = new RegisterRequest();
        req.setFullName("Test User");
        req.setEmail("MixedCase@EXAMPLE.COM");
        req.setMobileNumber("9876543210");
        req.setPassword("Test@1234");
        req.setConfirmPassword("Test@1234");

        when(userRepository.existsByEmail("mixedcase@example.com")).thenReturn(false);
        when(userRepository.existsByMobileNumber("9876543210")).thenReturn(false);
        when(userRepository.save(any())).thenAnswer(inv -> {
            User u = inv.getArgument(0);
            u.setId(1L);
            return u;
        });

        authService.register(req);

        verify(userRepository).existsByEmail("mixedcase@example.com");
        verify(userRepository).save(argThat(u -> u.getEmail().equals("mixedcase@example.com")));
    }

    // ============================================================
    // LOGIN TESTS
    // ============================================================

    @Test
    @DisplayName("Successful login by email")
    void login_byEmail_success() {
        String rawPassword = "Test@1234";
        User user = User.builder()
                .id(1L)
                .email("user@example.com")
                .mobileNumber("9876543210")
                .fullName("Test User")
                .passwordHash(realPasswordEncoder.encode(rawPassword))
                .active(true)
                .build();

        LoginRequest req = new LoginRequest();
        req.setIdentifier("user@example.com");
        req.setPassword(rawPassword);

        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(jwtTokenProvider.generateToken(eq(1L), anyString())).thenReturn("mock.jwt.token");
        when(jwtTokenProvider.getExpiry()).thenReturn(Instant.now().plusSeconds(1800));
        when(jwtConfig.getExpirationMs()).thenReturn(1800000L);
        when(authSessionRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        UserResponse response = authService.login(req, httpServletResponse);

        assertThat(response.getEmail()).isEqualTo("user@example.com");
        verify(cookieUtil).addAuthCookie(eq(httpServletResponse), eq("mock.jwt.token"), anyInt());
        verify(authSessionRepository).save(any(AuthSession.class));
    }

    @Test
    @DisplayName("Successful login by mobile number")
    void login_byMobile_success() {
        String rawPassword = "Test@1234";
        User user = User.builder()
                .id(1L)
                .email("user@example.com")
                .mobileNumber("9876543210")
                .fullName("Test User")
                .passwordHash(realPasswordEncoder.encode(rawPassword))
                .active(true)
                .build();

        LoginRequest req = new LoginRequest();
        req.setIdentifier("9876543210");
        req.setPassword(rawPassword);

        when(userRepository.findByMobileNumber("9876543210")).thenReturn(Optional.of(user));
        when(jwtTokenProvider.generateToken(eq(1L), anyString())).thenReturn("mock.jwt.token");
        when(jwtTokenProvider.getExpiry()).thenReturn(Instant.now().plusSeconds(1800));
        when(jwtConfig.getExpirationMs()).thenReturn(1800000L);
        when(authSessionRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        UserResponse response = authService.login(req, httpServletResponse);

        assertThat(response.getMobileNumber()).isEqualTo("9876543210");
    }

    @Test
    @DisplayName("Login with wrong password fails with generic error")
    void login_wrongPassword_throwsAuthException() {
        User user = User.builder()
                .id(1L)
                .email("user@example.com")
                .passwordHash(realPasswordEncoder.encode("Correct@1234"))
                .active(true)
                .build();

        LoginRequest req = new LoginRequest();
        req.setIdentifier("user@example.com");
        req.setPassword("Wrong@1234");

        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authService.login(req, httpServletResponse))
                .isInstanceOf(AuthException.class)
                .hasMessageContaining("Invalid credentials");
    }

    @Test
    @DisplayName("Login with unknown identifier fails with generic error (no enumeration)")
    void login_unknownIdentifier_throwsAuthException() {
        LoginRequest req = new LoginRequest();
        req.setIdentifier("nobody@example.com");
        req.setPassword("Test@1234");

        when(userRepository.findByEmail("nobody@example.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.login(req, httpServletResponse))
                .isInstanceOf(AuthException.class)
                .hasMessageContaining("Invalid credentials");
    }

    // ============================================================
    // LOGOUT TESTS
    // ============================================================

    @Test
    @DisplayName("Logout revokes the session")
    void logout_revokesSession() {
        User user = User.builder().id(1L).email("user@example.com")
                .passwordHash("hash").active(true).build();
        UserPrincipal principal = new UserPrincipal(user, "test-jti-123");

        when(authSessionRepository.revokeByJti(eq("test-jti-123"), any(Instant.class))).thenReturn(1);

        authService.logout(principal, httpServletResponse);

        verify(authSessionRepository).revokeByJti(eq("test-jti-123"), any(Instant.class));
        verify(cookieUtil).clearAuthCookie(httpServletResponse);
    }

    // ============================================================
    // FORGOT PASSWORD TESTS
    // ============================================================

    @Test
    @DisplayName("Forgot password for unknown identifier returns without error (no enumeration)")
    void forgotPassword_unknownIdentifier_noException() {
        when(userRepository.findByEmail("nobody@example.com")).thenReturn(Optional.empty());

        // Should complete without throwing
        assertThatNoException().isThrownBy(() -> authService.forgotPassword("nobody@example.com"));
        verify(emailService, never()).sendOtpEmail(any(), any(), any(), anyInt());
    }

    @Test
    @DisplayName("Forgot password sends OTP email for valid user")
    void forgotPassword_validUser_sendsEmail() {
        User user = User.builder()
                .id(1L)
                .email("user@example.com")
                .fullName("Test User")
                .passwordHash("hash")
                .active(true)
                .build();

        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(challengeRepository.findByUserIdOrderByCreatedAtDesc(1L)).thenReturn(List.of());
        when(challengeRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        authService.forgotPassword("user@example.com");

        verify(emailService).sendOtpEmail(eq("user@example.com"), eq("Test User"), anyString(), eq(5));
        verify(challengeRepository).save(any(PasswordRecoveryChallenge.class));
    }

    @Test
    @DisplayName("Forgot password by mobile number also works")
    void forgotPassword_byMobile_sendsEmail() {
        User user = User.builder()
                .id(1L)
                .email("user@example.com")
                .mobileNumber("9876543210")
                .fullName("Test User")
                .passwordHash("hash")
                .active(true)
                .build();

        when(userRepository.findByMobileNumber("9876543210")).thenReturn(Optional.of(user));
        when(challengeRepository.findByUserIdOrderByCreatedAtDesc(1L)).thenReturn(List.of());
        when(challengeRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        authService.forgotPassword("9876543210");

        verify(emailService).sendOtpEmail(eq("user@example.com"), eq("Test User"), anyString(), eq(5));
    }

    // ============================================================
    // OTP VERIFICATION TESTS
    // ============================================================

    @Test
    @DisplayName("OTP verification succeeds with correct OTP")
    void verifyOtp_correctOtp_returnsResetToken() {
        String rawOtp = "123456";
        String otpHash = realPasswordEncoder.encode(rawOtp);

        User user = User.builder().id(1L).email("user@example.com")
                .passwordHash("hash").active(true).build();

        PasswordRecoveryChallenge challenge = PasswordRecoveryChallenge.builder()
                .id(1L)
                .user(user)
                .otpHash(otpHash)
                .otpExpiresAt(Instant.now().plusSeconds(300))
                .attemptCount(0)
                .build();

        VerifyOtpRequest req = new VerifyOtpRequest();
        req.setIdentifier("user@example.com");
        req.setOtp(rawOtp);

        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(challengeRepository.findActiveByUserId(eq(1L), any())).thenReturn(List.of(challenge));
        when(challengeRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        VerifyOtpResponse response = authService.verifyOtp(req);

        assertThat(response.getResetToken()).isNotBlank();
        assertThat(response.getExpiresInSeconds()).isEqualTo(600L);
        verify(challengeRepository).save(argThat(c -> c.getResetTokenHash() != null));
    }

    @Test
    @DisplayName("OTP verification fails with wrong OTP")
    void verifyOtp_wrongOtp_throwsAuthException() {
        String otpHash = realPasswordEncoder.encode("111111");

        User user = User.builder().id(1L).email("user@example.com")
                .passwordHash("hash").active(true).build();

        PasswordRecoveryChallenge challenge = PasswordRecoveryChallenge.builder()
                .id(1L)
                .user(user)
                .otpHash(otpHash)
                .otpExpiresAt(Instant.now().plusSeconds(300))
                .attemptCount(0)
                .build();

        VerifyOtpRequest req = new VerifyOtpRequest();
        req.setIdentifier("user@example.com");
        req.setOtp("999999");

        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(challengeRepository.findActiveByUserId(eq(1L), any())).thenReturn(List.of(challenge));
        when(challengeRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        assertThatThrownBy(() -> authService.verifyOtp(req))
                .isInstanceOf(AuthException.class)
                .hasMessageContaining("Invalid or expired OTP");
    }

    @Test
    @DisplayName("OTP verification exhausts attempts after max failures")
    void verifyOtp_maxAttempts_challengeConsumed() {
        String otpHash = realPasswordEncoder.encode("111111");

        User user = User.builder().id(1L).email("user@example.com")
                .passwordHash("hash").active(true).build();

        PasswordRecoveryChallenge challenge = PasswordRecoveryChallenge.builder()
                .id(1L)
                .user(user)
                .otpHash(otpHash)
                .otpExpiresAt(Instant.now().plusSeconds(300))
                .attemptCount(4) // one more will exhaust it
                .build();

        VerifyOtpRequest req = new VerifyOtpRequest();
        req.setIdentifier("user@example.com");
        req.setOtp("999999");

        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(challengeRepository.findActiveByUserId(eq(1L), any())).thenReturn(List.of(challenge));
        when(challengeRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        assertThatThrownBy(() -> authService.verifyOtp(req))
                .isInstanceOf(AuthException.class);

        verify(challengeRepository).save(argThat(c -> c.getConsumedAt() != null));
    }

    @Test
    @DisplayName("OTP verification rejects already consumed challenge")
    void verifyOtp_consumedChallenge_throwsAuthException() {
        User user = User.builder().id(1L).email("user@example.com")
                .passwordHash("hash").active(true).build();

        VerifyOtpRequest req = new VerifyOtpRequest();
        req.setIdentifier("user@example.com");
        req.setOtp("123456");

        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        // findActiveByUserId returns empty (challenge expired/consumed)
        when(challengeRepository.findActiveByUserId(eq(1L), any())).thenReturn(List.of());

        assertThatThrownBy(() -> authService.verifyOtp(req))
                .isInstanceOf(AuthException.class)
                .hasMessageContaining("Invalid or expired OTP");
    }

    // ============================================================
    // RESET PASSWORD TESTS
    // ============================================================

    @Test
    @DisplayName("Password reset succeeds with valid token")
    void resetPassword_validToken_success() {
        User user = User.builder().id(1L).email("user@example.com")
                .passwordHash("oldhash").active(true).build();

        String rawToken = "valid-reset-token-string";
        // We need to compute the SHA-256 hash the same way AuthService does
        // We'll use the actual service method indirectly via the mock setup

        ResetPasswordRequest req = new ResetPasswordRequest();
        req.setResetToken(rawToken);
        req.setNewPassword("NewPass@1234");
        req.setConfirmPassword("NewPass@1234");

        // For this test, we stub the repository to return a challenge when queried with any hash
        PasswordRecoveryChallenge challenge = PasswordRecoveryChallenge.builder()
                .id(1L)
                .user(user)
                .resetTokenHash("any") // will be matched by the mock
                .resetTokenExpiresAt(Instant.now().plusSeconds(600))
                .build();

        when(challengeRepository.findByValidResetTokenHash(anyString(), any())).thenReturn(Optional.of(challenge));
        when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(challengeRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(authSessionRepository.revokeAllActiveSessionsForUser(eq(1L), any())).thenReturn(2);

        authService.resetPassword(req);

        verify(userRepository).save(argThat(u -> !u.getPasswordHash().equals("oldhash")));
        verify(authSessionRepository).revokeAllActiveSessionsForUser(eq(1L), any(Instant.class));
        verify(challengeRepository).save(argThat(c -> c.getResetTokenUsedAt() != null));
    }

    @Test
    @DisplayName("Password reset fails with invalid token")
    void resetPassword_invalidToken_throwsInvalidToken() {
        ResetPasswordRequest req = new ResetPasswordRequest();
        req.setResetToken("bad-token");
        req.setNewPassword("NewPass@1234");
        req.setConfirmPassword("NewPass@1234");

        when(challengeRepository.findByValidResetTokenHash(anyString(), any())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.resetPassword(req))
                .isInstanceOf(InvalidTokenException.class);
    }

    // ============================================================
    // CHANGE PASSWORD TESTS
    // ============================================================

    @Test
    @DisplayName("Change password succeeds with correct current password")
    void changePassword_success() {
        String rawCurrentPassword = "Current@1234";
        User user = User.builder()
                .id(1L)
                .email("user@example.com")
                .passwordHash(realPasswordEncoder.encode(rawCurrentPassword))
                .active(true)
                .build();

        UserPrincipal principal = new UserPrincipal(user, "jti-abc");

        ChangePasswordRequest req = new ChangePasswordRequest();
        req.setCurrentPassword(rawCurrentPassword);
        req.setNewPassword("NewPass@1234");
        req.setConfirmPassword("NewPass@1234");

        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(authSessionRepository.revokeAllActiveSessionsForUser(eq(1L), any())).thenReturn(1);

        authService.changePassword(principal, req);

        verify(userRepository).save(argThat(u ->
            !u.getPasswordHash().equals(realPasswordEncoder.encode(rawCurrentPassword))
        ));
        verify(authSessionRepository).revokeAllActiveSessionsForUser(eq(1L), any(Instant.class));
    }

    @Test
    @DisplayName("Change password fails with wrong current password")
    void changePassword_wrongCurrentPassword_throwsAuthException() {
        User user = User.builder()
                .id(1L)
                .email("user@example.com")
                .passwordHash(realPasswordEncoder.encode("Correct@1234"))
                .active(true)
                .build();

        UserPrincipal principal = new UserPrincipal(user, "jti-abc");

        ChangePasswordRequest req = new ChangePasswordRequest();
        req.setCurrentPassword("Wrong@1234");
        req.setNewPassword("NewPass@1234");
        req.setConfirmPassword("NewPass@1234");

        when(userRepository.findById(1L)).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authService.changePassword(principal, req))
                .isInstanceOf(AuthException.class)
                .hasMessageContaining("Current password is incorrect");
    }

    // ============================================================
    // SESSION INVALIDATION TESTS
    // ============================================================

    @Test
    @DisplayName("Password reset invalidates all active sessions")
    void resetPassword_invalidatesAllSessions() {
        User user = User.builder().id(5L).email("user@example.com")
                .passwordHash("oldhash").active(true).build();

        PasswordRecoveryChallenge challenge = PasswordRecoveryChallenge.builder()
                .id(1L).user(user)
                .resetTokenHash("any")
                .resetTokenExpiresAt(Instant.now().plusSeconds(600))
                .build();

        when(challengeRepository.findByValidResetTokenHash(anyString(), any())).thenReturn(Optional.of(challenge));
        when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(challengeRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(authSessionRepository.revokeAllActiveSessionsForUser(eq(5L), any())).thenReturn(3);

        ResetPasswordRequest req = new ResetPasswordRequest();
        req.setResetToken("some-token");
        req.setNewPassword("NewPass@1234");
        req.setConfirmPassword("NewPass@1234");

        authService.resetPassword(req);

        verify(authSessionRepository).revokeAllActiveSessionsForUser(eq(5L), any(Instant.class));
    }
}
