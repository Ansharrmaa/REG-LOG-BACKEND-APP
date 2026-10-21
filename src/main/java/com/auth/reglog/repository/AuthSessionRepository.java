package com.auth.reglog.repository;

import com.auth.reglog.entity.AuthSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface AuthSessionRepository extends JpaRepository<AuthSession, Long> {

    Optional<AuthSession> findByJti(String jti);

    List<AuthSession> findByUserIdAndRevokedAtIsNull(Long userId);

    @Modifying
    @Query("UPDATE AuthSession s SET s.revokedAt = :revokedAt WHERE s.user.id = :userId AND s.revokedAt IS NULL")
    int revokeAllActiveSessionsForUser(@Param("userId") Long userId, @Param("revokedAt") Instant revokedAt);

    @Modifying
    @Query("UPDATE AuthSession s SET s.revokedAt = :revokedAt WHERE s.jti = :jti AND s.revokedAt IS NULL")
    int revokeByJti(@Param("jti") String jti, @Param("revokedAt") Instant revokedAt);
}
