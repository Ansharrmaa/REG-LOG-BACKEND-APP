package com.auth.reglog.repository;

import com.auth.reglog.entity.PasswordRecoveryChallenge;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface PasswordRecoveryChallengeRepository extends JpaRepository<PasswordRecoveryChallenge, Long> {

    /** Find the most recent active (not consumed, not OTP-expired) challenge for a user. */
    @Query("SELECT p FROM PasswordRecoveryChallenge p WHERE p.user.id = :userId " +
           "AND p.consumedAt IS NULL AND p.otpExpiresAt > :now " +
           "ORDER BY p.createdAt DESC")
    List<PasswordRecoveryChallenge> findActiveByUserId(@Param("userId") Long userId,
                                                       @Param("now") Instant now);

    /** Find an active challenge that has a valid (unset/unexpired) reset token by reset token hash. */
    @Query("SELECT p FROM PasswordRecoveryChallenge p " +
           "WHERE p.resetTokenHash = :tokenHash " +
           "AND p.resetTokenUsedAt IS NULL " +
           "AND p.resetTokenExpiresAt > :now")
    Optional<PasswordRecoveryChallenge> findByValidResetTokenHash(@Param("tokenHash") String tokenHash,
                                                                   @Param("now") Instant now);

    /** Find the most recent challenge for a user regardless of status (for resend cooldown check). */
    @Query("SELECT p FROM PasswordRecoveryChallenge p WHERE p.user.id = :userId ORDER BY p.createdAt DESC")
    List<PasswordRecoveryChallenge> findByUserIdOrderByCreatedAtDesc(@Param("userId") Long userId);

    @Modifying
    @Query("UPDATE PasswordRecoveryChallenge p SET p.consumedAt = :now WHERE p.user.id = :userId AND p.consumedAt IS NULL")
    int consumeAllForUser(@Param("userId") Long userId, @Param("now") Instant now);
}
