package com.example.poctypesofauthentication.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/apikey")
public class ApiKeyController {
    @GetMapping("/data")
    public ResponseEntity<Map<String, Object>> data(@AuthenticationPrincipal UserDetails userDetails) {
        return ResponseEntity.ok(Map.of(
                "message", "Acesso via API Key",
                "loggedAs", userDetails.getUsername(),
                "authorities", userDetails.getAuthorities().toString()));
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> admin(@AuthenticationPrincipal UserDetails userDetails) {
        return ResponseEntity.ok(Map.of(
                "message", "Área admin via API Key",
                "loggedAs", userDetails.getUsername(),
                "authorities", userDetails.getAuthorities().toString()));
    }
}
