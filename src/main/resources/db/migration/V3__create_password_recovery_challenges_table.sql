-- V3: Create password_recovery_challenges table
-- Stores OTP challenges and their associated single-use reset tokens.
-- OTP hashes and reset token hashes are stored; never raw values.
CREATE TABLE password_recovery_challenges (
    id                     BIGINT       NOT NULL AUTO_INCREMENT,
    user_id                BIGINT       NOT NULL,
    otp_hash               VARCHAR(255) NOT NULL,
    otp_expires_at         TIMESTAMP    NOT NULL,
    attempt_count          INT          NOT NULL DEFAULT 0,
    consumed_at            TIMESTAMP    NULL,
    reset_token_hash       VARCHAR(255) NULL,
    reset_token_expires_at TIMESTAMP    NULL,
    reset_token_used_at    TIMESTAMP    NULL,
    created_at             TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    CONSTRAINT fk_prc_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX idx_prc_user_id    ON password_recovery_challenges (user_id);
CREATE INDEX idx_prc_created_at ON password_recovery_challenges (created_at);
