package com.auth.reglog.util;

import com.auth.reglog.config.JwtConfig;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

/**
 * Utility for creating and clearing the AUTH_TOKEN HttpOnly cookie.
 */
@Component
public class CookieUtil {

    private final JwtConfig jwtConfig;

    public CookieUtil(JwtConfig jwtConfig) {
        this.jwtConfig = jwtConfig;
    }

    /**
     * Set the AUTH_TOKEN HttpOnly cookie with the given JWT value.
     *
     * @param response   the HttpServletResponse
     * @param token      the signed JWT string
     * @param maxAgeSeconds cookie max-age in seconds
     */
    public void addAuthCookie(HttpServletResponse response, String token, int maxAgeSeconds) {
        Cookie cookie = buildCookie(token, maxAgeSeconds);
        response.addCookie(cookie);
        // Append SameSite attribute via Set-Cookie header (Java Servlet API doesn't expose SameSite)
        appendSameSite(response, cookie, "Lax");
    }

    /**
     * Clear the AUTH_TOKEN cookie. Matching attributes are required for the browser
     * to actually delete the cookie.
     */
    public void clearAuthCookie(HttpServletResponse response) {
        Cookie cookie = buildCookie("", 0);
        response.addCookie(cookie);
        appendSameSite(response, cookie, "Lax");
    }

    private Cookie buildCookie(String value, int maxAge) {
        Cookie cookie = new Cookie(jwtConfig.getCookieName(), value);
        cookie.setHttpOnly(true);
        cookie.setSecure(jwtConfig.isCookieSecure());
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);
        return cookie;
    }

    private void appendSameSite(HttpServletResponse response, Cookie cookie, String sameSite) {
        // Augment existing Set-Cookie header to add SameSite attribute
        String existing = response.getHeader("Set-Cookie");
        if (existing != null && existing.contains(cookie.getName())) {
            response.setHeader("Set-Cookie", existing + "; SameSite=" + sameSite);
        }
    }
}
