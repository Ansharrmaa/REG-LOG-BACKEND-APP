package com.auth.reglog.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * Request DTO for OTP verification during password reset flow.
 */
public class VerifyOtpRequest {

    @NotBlank(message = "Identifier (email or mobile number) is required")
    private String identifier;

    @NotBlank(message = "OTP is required")
    @Pattern(regexp = "^\\d{6}$", message = "OTP must be exactly 6 digits")
    private String otp;

    public VerifyOtpRequest() {
    }

    public VerifyOtpRequest(String identifier, String otp) {
        this.identifier = identifier;
        this.otp = otp;
    }

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    public String getOtp() {
        return otp;
    }

    public void setOtp(String otp) {
        this.otp = otp;
    }
}
