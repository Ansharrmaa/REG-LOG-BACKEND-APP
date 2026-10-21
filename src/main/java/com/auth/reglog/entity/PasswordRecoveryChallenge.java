package com.auth.reglog.entity;

import jakarta.persistence.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;

/**
 * Stores a password-recovery challenge record.
 * Contains:
 *   - BCrypt hash of the 6-digit OTP (never raw OTP)
 *   - OTP expiry and attempt counter
 *   - Optional SHA-256 hash of single-use reset token issued after OTP verification
 *
 * Only one active challenge per user should be relied upon at a time.
 * Old challenges are superseded by new ones on repeated forgot-password calls.
 */
@Entity
@Table(name = "password_recovery_challenges")
public class PasswordRecoveryChallenge {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    /** BCrypt hash of the 6-digit OTP. Raw OTP is never persisted. */
    @Column(name = "otp_hash", nullable = false)
    private String otpHash;

    @Column(name = "otp_expires_at", nullable = false)
    private Instant otpExpiresAt;

    /** Number of failed OTP verification attempts. */
    @Column(name = "attempt_count", nullable = false)
    private int attemptCount = 0;

    /** Set when OTP is successfully verified (challenge consumed for OTP). */
    @Column(name = "consumed_at")
    private Instant consumedAt;

    /** SHA-256 hex hash of the opaque reset token. Null until OTP verified. */
    @Column(name = "reset_token_hash")
    private String resetTokenHash;

    @Column(name = "reset_token_expires_at")
    private Instant resetTokenExpiresAt;

    /** Set when the reset token is used to change the password. */
    @Column(name = "reset_token_used_at")
    private Instant resetTokenUsedAt;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    public PasswordRecoveryChallenge() {
    }

    public PasswordRecoveryChallenge(Long id, User user, String otpHash, Instant otpExpiresAt, int attemptCount,
                                     Instant consumedAt, String resetTokenHash, Instant resetTokenExpiresAt,
                                     Instant resetTokenUsedAt, Instant createdAt) {
        this.id = id;
        this.user = user;
        this.otpHash = otpHash;
        this.otpExpiresAt = otpExpiresAt;
        this.attemptCount = attemptCount;
        this.consumedAt = consumedAt;
        this.resetTokenHash = resetTokenHash;
        this.resetTokenExpiresAt = resetTokenExpiresAt;
        this.resetTokenUsedAt = resetTokenUsedAt;
        this.createdAt = createdAt;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private Long id;
        private User user;
        private String otpHash;
        private Instant otpExpiresAt;
        private int attemptCount = 0;
        private Instant consumedAt;
        private String resetTokenHash;
        private Instant resetTokenExpiresAt;
        private Instant resetTokenUsedAt;
        private Instant createdAt;

        public Builder id(Long id) {
            this.id = id;
            return this;
        }

        public Builder user(User user) {
            this.user = user;
            return this;
        }

        public Builder otpHash(String otpHash) {
            this.otpHash = otpHash;
            return this;
        }

        public Builder otpExpiresAt(Instant otpExpiresAt) {
            this.otpExpiresAt = otpExpiresAt;
            return this;
        }

        public Builder attemptCount(int attemptCount) {
            this.attemptCount = attemptCount;
            return this;
        }

        public Builder consumedAt(Instant consumedAt) {
            this.consumedAt = consumedAt;
            return this;
        }

        public Builder resetTokenHash(String resetTokenHash) {
            this.resetTokenHash = resetTokenHash;
            return this;
        }

        public Builder resetTokenExpiresAt(Instant resetTokenExpiresAt) {
            this.resetTokenExpiresAt = resetTokenExpiresAt;
            return this;
        }

        public Builder resetTokenUsedAt(Instant resetTokenUsedAt) {
            this.resetTokenUsedAt = resetTokenUsedAt;
            return this;
        }

        public Builder createdAt(Instant createdAt) {
            this.createdAt = createdAt;
            return this;
        }

        public PasswordRecoveryChallenge build() {
            return new PasswordRecoveryChallenge(id, user, otpHash, otpExpiresAt, attemptCount,
                    consumedAt, resetTokenHash, resetTokenExpiresAt, resetTokenUsedAt, createdAt);
        }
    }

    public boolean isOtpExpired() {
        return Instant.now().isAfter(otpExpiresAt);
    }

    public boolean isOtpConsumed() {
        return consumedAt != null;
    }

    public boolean isResetTokenExpired() {
        return resetTokenExpiresAt != null && Instant.now().isAfter(resetTokenExpiresAt);
    }

    public boolean isResetTokenUsed() {
        return resetTokenUsedAt != null;
    }

    public boolean isResetTokenValid() {
        return resetTokenHash != null
                && !isResetTokenExpired()
                && !isResetTokenUsed();
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public String getOtpHash() {
        return otpHash;
    }

    public void setOtpHash(String otpHash) {
        this.otpHash = otpHash;
    }

    public Instant getOtpExpiresAt() {
        return otpExpiresAt;
    }

    public void setOtpExpiresAt(Instant otpExpiresAt) {
        this.otpExpiresAt = otpExpiresAt;
    }

    public int getAttemptCount() {
        return attemptCount;
    }

    public void setAttemptCount(int attemptCount) {
        this.attemptCount = attemptCount;
    }

    public Instant getConsumedAt() {
        return consumedAt;
    }

    public void setConsumedAt(Instant consumedAt) {
        this.consumedAt = consumedAt;
    }

    public String getResetTokenHash() {
        return resetTokenHash;
    }

    public void setResetTokenHash(String resetTokenHash) {
        this.resetTokenHash = resetTokenHash;
    }

    public Instant getResetTokenExpiresAt() {
        return resetTokenExpiresAt;
    }

    public void setResetTokenExpiresAt(Instant resetTokenExpiresAt) {
        this.resetTokenExpiresAt = resetTokenExpiresAt;
    }

    public Instant getResetTokenUsedAt() {
        return resetTokenUsedAt;
    }

    public void setResetTokenUsedAt(Instant resetTokenUsedAt) {
        this.resetTokenUsedAt = resetTokenUsedAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
}
