package com.auth.reglog.dto.request;

import jakarta.validation.constraints.NotBlank;

/**
 * Request DTO for forgot-password.
 * identifier can be registered email or mobile number.
 */
public class ForgotPasswordRequest {

    @NotBlank(message = "Identifier (email or mobile number) is required")
    private String identifier;

    public ForgotPasswordRequest() {
    }

    public ForgotPasswordRequest(String identifier) {
        this.identifier = identifier;
    }

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }
}
