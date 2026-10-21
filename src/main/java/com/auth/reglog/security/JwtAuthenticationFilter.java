package com.auth.reglog.security;

import com.auth.reglog.config.JwtConfig;
import com.auth.reglog.entity.AuthSession;
import com.auth.reglog.entity.User;
import com.auth.reglog.repository.AuthSessionRepository;
import com.auth.reglog.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;

/**
 * JWT authentication filter. Runs once per request.
 *
 * Reads the JWT from the AUTH_TOKEN HttpOnly cookie,
 * validates signature and expiry, performs server-side session revocation check,
 * and populates the Spring Security context if valid.
 *
 * Deliberately does NOT write any error response on failure — it simply
 * leaves the SecurityContext empty. The Spring Security AuthenticationEntryPoint
 * handles the resulting 401.
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final JwtTokenProvider jwtTokenProvider;
    private final JwtConfig jwtConfig;
    private final UserRepository userRepository;
    private final AuthSessionRepository authSessionRepository;

    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider, JwtConfig jwtConfig,
                                   UserRepository userRepository, AuthSessionRepository authSessionRepository) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.jwtConfig = jwtConfig;
        this.userRepository = userRepository;
        this.authSessionRepository = authSessionRepository;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        String token = extractTokenFromCookie(request);

        if (token != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            try {
                Claims claims = jwtTokenProvider.parseToken(token);
                String jti = claims.getId();
                Long userId = Long.parseLong(claims.getSubject());

                // Server-side session revocation check
                Optional<AuthSession> sessionOpt = authSessionRepository.findByJti(jti);
                if (sessionOpt.isPresent() && sessionOpt.get().isValid()) {
                    Optional<User> userOpt = userRepository.findById(userId);
                    if (userOpt.isPresent() && userOpt.get().isActive()) {
                        UserPrincipal principal = new UserPrincipal(userOpt.get(), jti);
                        UsernamePasswordAuthenticationToken authentication =
                                new UsernamePasswordAuthenticationToken(
                                        principal, null, principal.getAuthorities()
                                );
                        authentication.setDetails(
                                new WebAuthenticationDetailsSource().buildDetails(request)
                        );
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    }
                }
                // If session not found or revoked: silently skip — 401 handled downstream
            } catch (JwtException e) {
                // Invalid/expired/malformed JWT — do not populate context
                log.debug("JWT validation failed: {}", e.getMessage());
            } catch (NumberFormatException e) {
                log.debug("Malformed JWT subject claim");
            }
        }

        filterChain.doFilter(request, response);
    }

    private String extractTokenFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return null;
        return Arrays.stream(cookies)
                .filter(c -> jwtConfig.getCookieName().equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }
}
