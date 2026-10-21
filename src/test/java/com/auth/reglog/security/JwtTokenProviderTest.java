package com.auth.reglog.security;

import com.auth.reglog.config.JwtConfig;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.Base64;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class JwtTokenProviderTest {

    @Mock
    private JwtConfig jwtConfig;

    private JwtTokenProvider jwtTokenProvider;

    // A valid 256-bit Base64 secret for testing
    private static final String TEST_SECRET =
            Base64.getEncoder().encodeToString("test-secret-key-must-be-32-bytes!".getBytes());

    @BeforeEach
    void setUp() {
        when(jwtConfig.getSecret()).thenReturn(TEST_SECRET);
        when(jwtConfig.getExpirationMs()).thenReturn(1800000L);
        when(jwtConfig.getIssuer()).thenReturn("test-issuer");
        jwtTokenProvider = new JwtTokenProvider(jwtConfig);
    }

    @Test
    @DisplayName("Generated token can be parsed and claims are correct")
    void generateAndParse_success() {
        Long userId = 42L;
        String jti = JwtTokenProvider.generateJti();

        String token = jwtTokenProvider.generateToken(userId, jti);

        assertThat(token).isNotBlank();

        Claims claims = jwtTokenProvider.parseToken(token);
        assertThat(claims.getSubject()).isEqualTo("42");
        assertThat(claims.getId()).isEqualTo(jti);
        assertThat(claims.getIssuer()).isEqualTo("test-issuer");
    }

    @Test
    @DisplayName("getUserIdFromToken extracts userId correctly")
    void getUserIdFromToken_success() {
        String jti = JwtTokenProvider.generateJti();
        String token = jwtTokenProvider.generateToken(99L, jti);

        Long userId = jwtTokenProvider.getUserIdFromToken(token);

        assertThat(userId).isEqualTo(99L);
    }

    @Test
    @DisplayName("getJtiFromToken extracts jti correctly")
    void getJtiFromToken_success() {
        String expectedJti = JwtTokenProvider.generateJti();
        String token = jwtTokenProvider.generateToken(1L, expectedJti);

        String extractedJti = jwtTokenProvider.getJtiFromToken(token);

        assertThat(extractedJti).isEqualTo(expectedJti);
    }

    @Test
    @DisplayName("Parsing an expired token throws JwtException")
    void parseToken_expired_throwsJwtException() {
        // Create provider with -1s expiry (already expired)
        when(jwtConfig.getExpirationMs()).thenReturn(-1000L);
        JwtTokenProvider expiredProvider = new JwtTokenProvider(jwtConfig);

        String jti = JwtTokenProvider.generateJti();
        String expiredToken = expiredProvider.generateToken(1L, jti);

        assertThatThrownBy(() -> jwtTokenProvider.parseToken(expiredToken))
                .isInstanceOf(JwtException.class);
    }

    @Test
    @DisplayName("Parsing a tampered token throws JwtException")
    void parseToken_tamperedSignature_throwsJwtException() {
        String jti = JwtTokenProvider.generateJti();
        String token = jwtTokenProvider.generateToken(1L, jti);
        String tampered = token.substring(0, token.length() - 4) + "XXXX";

        assertThatThrownBy(() -> jwtTokenProvider.parseToken(tampered))
                .isInstanceOf(JwtException.class);
    }

    @Test
    @DisplayName("Parsing a completely invalid token throws JwtException")
    void parseToken_malformed_throwsJwtException() {
        assertThatThrownBy(() -> jwtTokenProvider.parseToken("not.a.jwt"))
                .isInstanceOf(JwtException.class);
    }

    @Test
    @DisplayName("Token signed with different secret is rejected")
    void parseToken_wrongSecret_throwsJwtException() {
        String differentSecret = Base64.getEncoder()
                .encodeToString("different-secret-must-be-32-bytes".getBytes());
        when(jwtConfig.getSecret()).thenReturn(differentSecret);
        JwtTokenProvider otherProvider = new JwtTokenProvider(jwtConfig);

        String jti = JwtTokenProvider.generateJti();
        String tokenFromOther = otherProvider.generateToken(1L, jti);

        // Reset to original secret
        when(jwtConfig.getSecret()).thenReturn(TEST_SECRET);
        JwtTokenProvider originalProvider = new JwtTokenProvider(jwtConfig);

        assertThatThrownBy(() -> originalProvider.parseToken(tokenFromOther))
                .isInstanceOf(JwtException.class);
    }

    @Test
    @DisplayName("generateJti produces a unique UUID each time")
    void generateJti_isUnique() {
        String jti1 = JwtTokenProvider.generateJti();
        String jti2 = JwtTokenProvider.generateJti();

        assertThat(jti1).isNotEqualTo(jti2);
        assertThat(jti1).matches("[0-9a-f-]{36}");
    }
}
