-- V1: Create users table
CREATE TABLE users (
    id            BIGINT          NOT NULL AUTO_INCREMENT,
    full_name     VARCHAR(100)    NOT NULL,
    email         VARCHAR(255)    NOT NULL,
    mobile_number VARCHAR(10)     NOT NULL,
    password_hash VARCHAR(255)    NOT NULL,
    is_active     BOOLEAN         NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    CONSTRAINT uq_users_email         UNIQUE (email),
    CONSTRAINT uq_users_mobile_number UNIQUE (mobile_number)
);

CREATE INDEX idx_users_email         ON users (email);
CREATE INDEX idx_users_mobile_number ON users (mobile_number);
