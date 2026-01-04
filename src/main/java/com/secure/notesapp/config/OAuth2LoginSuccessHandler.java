package com.secure.notesapp.config;

import com.secure.notesapp.model.AppRole;
import com.secure.notesapp.model.Role;
import com.secure.notesapp.model.User;
import com.secure.notesapp.repository.RoleRepository;
import com.secure.notesapp.security.jwt.JwtUtils;
import com.secure.notesapp.security.service.UserDetailsImpl;
import com.secure.notesapp.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final UserService userService;
    private final JwtUtils jwtUtils;
    private final RoleRepository roleRepository;

    @Value("${frontend.url}")
    private String frontendUrl;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException {

        DefaultOAuth2User oauth2User = (DefaultOAuth2User) authentication.getPrincipal();

        String email = (String) oauth2User.getAttributes().get("email");
        String username = (String) oauth2User.getAttributes().get("username");
        String provider = (String) oauth2User.getAttributes().get("provider");

        if (email == null) {
            throw new IllegalStateException("OAuth2 authentication missing email");
        }

        User user = userService.findByEmail(email)
                .orElseGet(() -> registerNewUser(email, username, provider));

        String jwt = jwtUtils.generateTokenFromUsername(
                UserDetailsImpl.build(user)
        );

        String redirectUrl = UriComponentsBuilder
                .fromUriString(frontendUrl + "/oauth2/redirect")
                .queryParam("token", jwt)
                .build()
                .toUriString();

        response.sendRedirect(redirectUrl);
    }

    private User registerNewUser(String email, String username, String provider) {

        Role role = roleRepository.findByRoleName(AppRole.ROLE_USER)
                .orElseThrow(() -> new IllegalStateException("ROLE_USER not found"));

        User user = new User();
        user.setEmail(email);
        user.setUserName(username);
        user.setRole(role);
        user.setSignUpMethod(provider);

        return userService.registerUser(user);
    }
}
