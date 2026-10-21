package com.auth.reglog.dto.response;

/**
 * Response after successful OTP verification.
 * Contains a single-use opaque reset token.
 * The raw token is only issued once, over HTTPS.
 */
public class VerifyOtpResponse {

    private String resetToken;
    private long expiresInSeconds;

    public VerifyOtpResponse() {
    }

    public VerifyOtpResponse(String resetToken, long expiresInSeconds) {
        this.resetToken = resetToken;
        this.expiresInSeconds = expiresInSeconds;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String resetToken;
        private long expiresInSeconds;

        public Builder resetToken(String resetToken) {
            this.resetToken = resetToken;
            return this;
        }

        public Builder expiresInSeconds(long expiresInSeconds) {
            this.expiresInSeconds = expiresInSeconds;
            return this;
        }

        public VerifyOtpResponse build() {
            return new VerifyOtpResponse(resetToken, expiresInSeconds);
        }
    }

    public String getResetToken() {
        return resetToken;
    }

    public void setResetToken(String resetToken) {
        this.resetToken = resetToken;
    }

    public long getExpiresInSeconds() {
        return expiresInSeconds;
    }

    public void setExpiresInSeconds(long expiresInSeconds) {
        this.expiresInSeconds = expiresInSeconds;
    }
}
