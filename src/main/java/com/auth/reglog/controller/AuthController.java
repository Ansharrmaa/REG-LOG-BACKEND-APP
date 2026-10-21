package com.auth.reglog.controller;

import com.auth.reglog.dto.request.*;
import com.auth.reglog.dto.response.*;
import com.auth.reglog.security.UserPrincipal;
import com.auth.reglog.service.AuthService;
import com.auth.reglog.service.RateLimitService;
import com.auth.reglog.util.CookieUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Authentication controller. Handles all /api/v1/auth/** endpoints.
 *
 * Controllers contain only HTTP request/response handling.
 * All business logic is delegated to AuthService.
 */
@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Authentication", description = "Registration, login, session, and password recovery endpoints")
public class AuthController {

    private final AuthService authService;
    private final RateLimitService rateLimitService;
    private final CookieUtil cookieUtil;

    public AuthController(AuthService authService, RateLimitService rateLimitService, CookieUtil cookieUtil) {
        this.authService = authService;
        this.rateLimitService = rateLimitService;
        this.cookieUtil = cookieUtil;
    }

    // ============================================================
    // CSRF TOKEN INITIALIZATION
    // ============================================================

    @GetMapping("/csrf")
    @Operation(
        summary = "Initialize CSRF token",
        description = "Returns the CSRF token and expected header name. " +
                      "The browser also receives the XSRF-TOKEN cookie. " +
                      "Submit the token value in the X-XSRF-TOKEN header on mutating requests."
    )
    public ResponseEntity<Map<String, String>> csrf(CsrfToken csrfToken) {
        // Accessing csrfToken.getToken() triggers lazy initialization
        return ResponseEntity.ok(Map.of(
            "token", csrfToken.getToken(),
            "headerName", csrfToken.getHeaderName(),
            "parameterName", csrfToken.getParameterName()
        ));
    }

    // ============================================================
    // REGISTRATION
    // ============================================================

    @PostMapping("/register")
    @Operation(
        summary = "Register a new user",
        description = "Creates a new user account. Email and mobile number must be unique. " +
                      "Password is stored as a BCrypt hash. confirmPassword is not stored."
    )
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request) {
        UserResponse userResponse = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(userResponse);
    }

    // ============================================================
    // LOGIN
    // ============================================================

    @PostMapping("/login")
    @Operation(
        summary = "Login with email or mobile number",
        description = "Authenticates a user and issues a signed JWT in an HttpOnly AUTH_TOKEN cookie. " +
                      "identifier can be a registered email address or a 10-digit mobile number. " +
                      "Rate limited: 5 attempts per IP per minute."
    )
    public ResponseEntity<UserResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest servletRequest,
            HttpServletResponse response
    ) {
        rateLimitService.checkLoginRateLimit(getClientIp(servletRequest));
        UserResponse userResponse = authService.login(request, response);
        return ResponseEntity.ok(userResponse);
    }

    // ============================================================
    // LOGOUT
    // ============================================================

    @PostMapping("/logout")
    @Operation(
        summary = "Logout",
        description = "Revokes the current session server-side and clears the AUTH_TOKEN cookie.",
        security = @SecurityRequirement(name = "cookieAuth")
    )
    public ResponseEntity<ApiResponse> logout(
            @AuthenticationPrincipal UserPrincipal principal,
            HttpServletResponse response
    ) {
        authService.logout(principal, response);
        return ResponseEntity.ok(ApiResponse.of("Logged out successfully"));
    }

    // ============================================================
    // CURRENT USER
    // ============================================================

    @GetMapping("/me")
    @Operation(
        summary = "Get current authenticated user",
        description = "Returns safe user details. Does not expose passwords, hashes, or tokens.",
        security = @SecurityRequirement(name = "cookieAuth")
    )
    public ResponseEntity<UserResponse> me(@AuthenticationPrincipal UserPrincipal principal) {
        return ResponseEntity.ok(authService.getCurrentUser(principal));
    }

    // ============================================================
    // FORGOT PASSWORD
    // ============================================================

    @PostMapping("/forgot-password")
    @Operation(
        summary = "Request password reset OTP",
        description = "Sends a 6-digit OTP to the registered email. " +
                      "Always returns a generic response regardless of account existence. " +
                      "Rate limited: 3 requests per IP per 5 minutes."
    )
    public ResponseEntity<ApiResponse> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request,
            HttpServletRequest servletRequest
    ) {
        rateLimitService.checkForgotPasswordRateLimit(getClientIp(servletRequest));
        authService.forgotPassword(request.getIdentifier());
        return ResponseEntity.ok(
            ApiResponse.of("If an account exists with that identifier, a recovery OTP has been sent to the registered email.")
        );
    }

    // ============================================================
    // VERIFY OTP
    // ============================================================

    @PostMapping("/verify-reset-otp")
    @Operation(
        summary = "Verify password reset OTP",
        description = "Verifies the 6-digit OTP. On success, returns a single-use opaque reset token " +
                      "valid for 10 minutes. Maximum 5 incorrect attempts."
    )
    public ResponseEntity<VerifyOtpResponse> verifyOtp(@Valid @RequestBody VerifyOtpRequest request) {
        VerifyOtpResponse verifyOtpResponse = authService.verifyOtp(request);
        return ResponseEntity.ok(verifyOtpResponse);
    }

    // ============================================================
    // RESET PASSWORD
    // ============================================================

    @PostMapping("/reset-password")
    @Operation(
        summary = "Reset password using reset token",
        description = "Resets the user's password using a valid single-use reset token. " +
                      "Invalidates all active sessions after successful reset."
    )
    public ResponseEntity<ApiResponse> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        authService.resetPassword(request);
        return ResponseEntity.ok(ApiResponse.of(
            "Password has been reset successfully. Please login with your new password."
        ));
    }

    // ============================================================
    // CHANGE PASSWORD (authenticated)
    // ============================================================

    @PostMapping("/change-password")
    @Operation(
        summary = "Change password (authenticated)",
        description = "Changes the authenticated user's password. Requires the current password. " +
                      "All active sessions are revoked. User must re-login.",
        security = @SecurityRequirement(name = "cookieAuth")
    )
    public ResponseEntity<ApiResponse> changePassword(
            @AuthenticationPrincipal UserPrincipal principal,
            @Valid @RequestBody ChangePasswordRequest request,
            HttpServletResponse response
    ) {
        authService.changePassword(principal, request);
        cookieUtil.clearAuthCookie(response);
        return ResponseEntity.ok(ApiResponse.of("Password changed successfully. Please login again."));
    }

    // ============================================================
    // HELPERS
    // ============================================================

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isBlank()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
