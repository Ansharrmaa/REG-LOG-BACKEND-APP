package com.auth.reglog.dto.request;

import jakarta.validation.constraints.NotBlank;

/**
 * Request DTO for login.
 * identifier can be a registered email or a 10-digit mobile number.
 */
public class LoginRequest {

    @NotBlank(message = "Identifier (email or mobile number) is required")
    private String identifier;

    @NotBlank(message = "Password is required")
    private String password;

    public LoginRequest() {
    }

    public LoginRequest(String identifier, String password) {
        this.identifier = identifier;
        this.password = password;
    }

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
