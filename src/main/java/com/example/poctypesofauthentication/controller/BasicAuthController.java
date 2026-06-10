package com.example.poctypesofauthentication.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/admin")
public class BasicAuthController {

    /**
     * Protegido pela regra do SecurityFilterChain: hasRole("ADMIN").
     * Usuários com role USER receberão 403 Forbidden.
     */
    @GetMapping("/dashboard")
    public ResponseEntity<Map<String, Object>> dashboard(@AuthenticationPrincipal UserDetails userDetails) {
        return ResponseEntity.ok(Map.of(
                "message", "Área administrativa - apenas ADMIN",
                "loggedAs", userDetails.getUsername(),
                "users", List.of("admin", "user")
        ));
    }

    /**
     * Demonstração do @PreAuthorize a nível de método (requer @EnableMethodSecurity).
     * Complementa as regras do SecurityFilterChain com controle mais granular.
     */
    @GetMapping("/settings")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> settings() {
        return ResponseEntity.ok(Map.of(
                "feature.basicAuth", "enabled",
                "session.policy", "STATELESS",
                "password.encoder", "BCrypt"
        ));
    }
}
