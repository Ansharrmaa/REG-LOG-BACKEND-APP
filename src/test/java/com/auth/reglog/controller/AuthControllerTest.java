package com.auth.reglog.controller;

import com.auth.reglog.config.JwtConfig;
import com.auth.reglog.config.SecurityConfig;
import com.auth.reglog.dto.request.RegisterRequest;
import com.auth.reglog.dto.response.UserResponse;
import com.auth.reglog.exception.DuplicateResourceException;
import com.auth.reglog.repository.AuthSessionRepository;
import com.auth.reglog.repository.UserRepository;
import com.auth.reglog.security.JwtAuthenticationFilter;
import com.auth.reglog.security.JwtTokenProvider;
import com.auth.reglog.service.AuthService;
import com.auth.reglog.service.RateLimitService;
import com.auth.reglog.util.CookieUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Web layer tests for AuthController using MockMvc with Spring Security.
 * No real database or SMTP required.
 */
@WebMvcTest(AuthController.class)
@Import({
    SecurityConfig.class,
    JwtAuthenticationFilter.class,
    JwtTokenProvider.class,
    JwtConfig.class,
    CookieUtil.class
})
@TestPropertySource(properties = {
    "app.jwt.secret=dGVzdFNlY3JldEtleUZvclRlc3RpbmdQdXJwb3Nlc09ubHkxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
    "app.jwt.expiration-ms=1800000",
    "app.jwt.issuer=test",
    "app.jwt.cookie-name=AUTH_TOKEN",
    "app.jwt.cookie-secure=false",
    "app.cors.allowed-origin=http://localhost:5173",
    "app.mail.from=test@test.com",
    "app.rate-limit.login.capacity=100",
    "app.rate-limit.login.refill-tokens=100",
    "app.rate-limit.login.refill-seconds=60",
    "app.rate-limit.forgot-password.capacity=100",
    "app.rate-limit.forgot-password.refill-tokens=100",
    "app.rate-limit.forgot-password.refill-seconds=300"
})
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private AuthService authService;

    @MockBean
    private RateLimitService rateLimitService;

    @MockBean
    private UserRepository userRepository;

    @MockBean
    private AuthSessionRepository authSessionRepository;

    // ============================================================
    // REGISTRATION TESTS
    // ============================================================

    @Test
    @DisplayName("POST /register returns 201 with valid request")
    void register_validRequest_returns201() throws Exception {
        RegisterRequest req = new RegisterRequest();
        req.setFullName("Test User");
        req.setEmail("user@example.com");
        req.setMobileNumber("9876543210");
        req.setPassword("Test@1234");
        req.setConfirmPassword("Test@1234");

        UserResponse userResponse = UserResponse.builder()
                .id(1L)
                .fullName("Test User")
                .email("user@example.com")
                .mobileNumber("9876543210")
                .build();

        when(authService.register(any())).thenReturn(userResponse);

        mockMvc.perform(post("/api/v1/auth/register")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value("user@example.com"))
                .andExpect(jsonPath("$.fullName").value("Test User"))
                .andExpect(jsonPath("$.id").value(1));
    }

    @Test
    @DisplayName("POST /register returns 400 with invalid email format")
    void register_invalidEmail_returns400() throws Exception {
        RegisterRequest req = new RegisterRequest();
        req.setFullName("Test User");
        req.setEmail("not-an-email");
        req.setMobileNumber("9876543210");
        req.setPassword("Test@1234");
        req.setConfirmPassword("Test@1234");

        mockMvc.perform(post("/api/v1/auth/register")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.email").exists());
    }

    @Test
    @DisplayName("POST /register returns 400 with short mobile number")
    void register_invalidMobile_returns400() throws Exception {
        RegisterRequest req = new RegisterRequest();
        req.setFullName("Test User");
        req.setEmail("user@example.com");
        req.setMobileNumber("12345"); // too short
        req.setPassword("Test@1234");
        req.setConfirmPassword("Test@1234");

        mockMvc.perform(post("/api/v1/auth/register")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.mobileNumber").exists());
    }

    @Test
    @DisplayName("POST /register returns 400 when passwords do not match")
    void register_passwordMismatch_returns400() throws Exception {
        RegisterRequest req = new RegisterRequest();
        req.setFullName("Test User");
        req.setEmail("user@example.com");
        req.setMobileNumber("9876543210");
        req.setPassword("Test@1234");
        req.setConfirmPassword("Different@1234");

        mockMvc.perform(post("/api/v1/auth/register")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("POST /register returns 409 when email already exists")
    void register_duplicateEmail_returns409() throws Exception {
        RegisterRequest req = new RegisterRequest();
        req.setFullName("Test User");
        req.setEmail("existing@example.com");
        req.setMobileNumber("9876543210");
        req.setPassword("Test@1234");
        req.setConfirmPassword("Test@1234");

        when(authService.register(any()))
                .thenThrow(new DuplicateResourceException("An account with this email already exists"));

        mockMvc.perform(post("/api/v1/auth/register")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").exists());
    }

    @Test
    @DisplayName("POST /register returns 400 with weak password")
    void register_weakPassword_returns400() throws Exception {
        RegisterRequest req = new RegisterRequest();
        req.setFullName("Test User");
        req.setEmail("user@example.com");
        req.setMobileNumber("9876543210");
        req.setPassword("password"); // no uppercase, digit, or special char
        req.setConfirmPassword("password");

        mockMvc.perform(post("/api/v1/auth/register")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.password").exists());
    }

    @Test
    @DisplayName("POST /register returns 400 with short full name")
    void register_shortFullName_returns400() throws Exception {
        RegisterRequest req = new RegisterRequest();
        req.setFullName("AB"); // less than 3 chars
        req.setEmail("user@example.com");
        req.setMobileNumber("9876543210");
        req.setPassword("Test@1234");
        req.setConfirmPassword("Test@1234");

        mockMvc.perform(post("/api/v1/auth/register")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.fullName").exists());
    }

    @Test
    @DisplayName("POST /register returns 400 with missing fields")
    void register_missingFields_returns400() throws Exception {
        mockMvc.perform(post("/api/v1/auth/register")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors").exists());
    }

    // ============================================================
    // AUTHENTICATION REQUIRED TESTS
    // ============================================================

    @Test
    @DisplayName("GET /me returns 401 without authentication cookie")
    void me_unauthenticated_returns401() throws Exception {
        mockMvc.perform(get("/api/v1/auth/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("POST /logout returns 401 without authentication")
    void logout_unauthenticated_returns401() throws Exception {
        mockMvc.perform(post("/api/v1/auth/logout")
                .with(csrf()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("POST /change-password returns 401 without authentication")
    void changePassword_unauthenticated_returns401() throws Exception {
        mockMvc.perform(post("/api/v1/auth/change-password")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"currentPassword\":\"Old@1234\",\"newPassword\":\"New@1234\",\"confirmPassword\":\"New@1234\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("GET /csrf returns CSRF token")
    void csrf_returnsToken() throws Exception {
        mockMvc.perform(get("/api/v1/auth/csrf"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists())
                .andExpect(jsonPath("$.headerName").exists());
    }

    // ============================================================
    // FORGOT PASSWORD — SENSITIVE INFO NOT LEAKED
    // ============================================================

    @Test
    @DisplayName("POST /forgot-password always returns 200 with generic message")
    void forgotPassword_alwaysReturns200() throws Exception {
        mockMvc.perform(post("/api/v1/auth/forgot-password")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"identifier\":\"nobody@example.com\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").exists());
    }
}
