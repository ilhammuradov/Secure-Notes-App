package com.secure.notesapp.repository;

import com.secure.notesapp.model.PasswordResetToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {
    @Modifying
    @Query("update PasswordResetToken p set p.used = true where p.user.id = :userId and p.used = false")
    void invalidateExistingTokens(Long userId);

    Optional<PasswordResetToken> findByToken(String token);
}
