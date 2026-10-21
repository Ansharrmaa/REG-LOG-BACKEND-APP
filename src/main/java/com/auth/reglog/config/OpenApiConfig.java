package com.auth.reglog.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
    info = @Info(
        title = "Registration & Login Service API",
        version = "1.0.0",
        description = "Authentication service for e-commerce application. " +
                      "Provides user registration, login (email or mobile), JWT-based session management, " +
                      "password recovery via email OTP, and password change. " +
                      "Authentication uses HttpOnly cookies. CSRF protection is required on mutating requests.",
        contact = @Contact(name = "Backend Team")
    ),
    servers = {
        @Server(url = "http://localhost:8080", description = "Local Development Server")
    }
)
@SecurityScheme(
    name = "cookieAuth",
    type = SecuritySchemeType.APIKEY,
    in = SecuritySchemeIn.COOKIE,
    paramName = "AUTH_TOKEN",
    description = "HttpOnly JWT cookie. Set automatically after successful login."
)
public class OpenApiConfig {
}
