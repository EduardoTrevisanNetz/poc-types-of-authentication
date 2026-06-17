package com.example.poctypesofauthentication.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/social")
public class SocialLoginController {
    @GetMapping("/profile")
    public ResponseEntity<Map<String, Object>> profile(@AuthenticationPrincipal OAuth2User oAuth2User) {
        return ResponseEntity.ok(Map.of(
                "message", "Autenticado via GitHub",
                "login", oAuth2User.getAttribute("login"),
                "name", String.valueOf(oAuth2User.getAttribute("name")),
                "email", String.valueOf(oAuth2User.getAttribute("email")),
                "avatarUrl", String.valueOf(oAuth2User.getAttribute("avatar_url"))));
    }
}
