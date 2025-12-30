package com.secure.notesapp.repository;

import com.secure.notesapp.model.AppRole;
import com.secure.notesapp.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByRoleName(AppRole role);
}
