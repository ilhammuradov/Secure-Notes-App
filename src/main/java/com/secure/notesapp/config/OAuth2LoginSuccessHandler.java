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
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.Map;

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
        Map<String, Object> attributes = oauth2User.getAttributes();

        OAuth2AuthenticationToken authToken = (OAuth2AuthenticationToken) authentication;
        String provider = authToken.getAuthorizedClientRegistrationId();

        String email = (String) attributes.get("email");

        String username = (String) attributes.get("username");

        if (username == null) {
            username = (String) attributes.get("login");
        }

        if (username == null) {
            username = email.split("@")[0];
        }

        if (email == null) {
            throw new IllegalStateException("OAuth2 provider did not return an email address.");
        }

        String finalUsername = username;
        String finalProvider = provider;

        User user = userService.findByEmail(email)
                .orElseGet(() -> registerNewUser(email, finalUsername, finalProvider));

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