-- V2: Create auth_sessions table for persistent JWT session revocation
CREATE TABLE auth_sessions (
    id         BIGINT      NOT NULL AUTO_INCREMENT,
    user_id    BIGINT      NOT NULL,
    jti        VARCHAR(36) NOT NULL,
    created_at TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP   NOT NULL,
    revoked_at TIMESTAMP   NULL,

    PRIMARY KEY (id),
    CONSTRAINT uq_sessions_jti UNIQUE (jti),
    CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX idx_sessions_user_id  ON auth_sessions (user_id);
CREATE INDEX idx_sessions_jti      ON auth_sessions (jti);
CREATE INDEX idx_sessions_expires  ON auth_sessions (expires_at);
