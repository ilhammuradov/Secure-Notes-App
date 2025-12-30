package com.secure.notesapp.service;

import com.secure.notesapp.dto.UserDTO;
import com.secure.notesapp.model.Role;
import com.secure.notesapp.model.User;

import java.util.List;
import java.util.Optional;

public interface UserService {
    void updateUserRole(Long userId, String roleName);

    List<User> getAllUsers();

    UserDTO getUserById(Long id);

    User findByUsername(String username);

    void updatePassword(Long userId, String password);

    void generatePasswordResetToken(String email);

    void updateAccountLockStatus(Long userId, boolean lock);

    void updateAccountExpiryStatus(Long userId, boolean expire);

    void updateAccountEnabledStatus(Long userId, boolean enabled);

    void updateCredentialsExpiryStatus(Long userId, boolean expire);

    List<Role> getAllRoles();

    void resetPassword(String token, String newPassword);
}

