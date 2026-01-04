package com.secure.notesapp.config;

import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest)
            throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);

        String registrationId =
                userRequest.getClientRegistration().getRegistrationId();

        Map<String, Object> attributes = oAuth2User.getAttributes();

        String email;
        String username;
        String idAttributeKey;

        if ("google".equals(registrationId)) {
            email = (String) attributes.get("email");
            username = email != null ? email.split("@")[0] : null;
            idAttributeKey = "sub";
        }
        else if ("github".equals(registrationId)) {
            email = (String) attributes.get("email");
            username = (String) attributes.get("login");
            idAttributeKey = "id";
        }
        else {
            throw new OAuth2AuthenticationException("Unsupported OAuth2 provider");
        }

        if (email == null || email.isBlank()) {
            throw new OAuth2AuthenticationException("Email not found from OAuth2 provider");
        }

        Map<String, Object> normalizedAttributes = new HashMap<>(attributes);
        normalizedAttributes.put("email", email);
        normalizedAttributes.put("username", username);
        normalizedAttributes.put("provider", registrationId);

        return new DefaultOAuth2User(
                oAuth2User.getAuthorities(),
                normalizedAttributes,
                idAttributeKey
        );
    }
}
