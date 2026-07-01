package com.example.poctypesofauthentication.controller;

import com.example.poctypesofauthentication.service.JwtService;
import com.example.poctypesofauthentication.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/jwt")
@RequiredArgsConstructor
public class JWTController {

    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody Map<String, String> credentials) {
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        credentials.get("username"),
                        credentials.get("password")));

        UserDetails userDetails = (UserDetails) auth.getPrincipal();
        String accessToken  = jwtService.generateAccessToken(userDetails);
        String refreshToken = refreshTokenService.generate(userDetails.getUsername());

        return ResponseEntity.ok(Map.of(
                "access_token",  accessToken,
                "refresh_token", refreshToken,
                "token_type",    "Bearer",
                "expires_in",    "900"
        ));
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody Map<String, String> body) {
        String refreshToken = body.get("refresh_token");

        if (refreshToken == null || refreshToken.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "refresh_token ausente"));
        }

        if (!refreshTokenService.isValid(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Refresh token inválido ou expirado"));
        }

        String username = refreshTokenService.extractUsername(refreshToken);
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        // Rotation: revoga o token antigo e emite um novo par
        refreshTokenService.revoke(refreshToken);
        String newAccessToken  = jwtService.generateAccessToken(userDetails);
        String newRefreshToken = refreshTokenService.generate(username);

        return ResponseEntity.ok(Map.of(
                "access_token",  newAccessToken,
                "refresh_token", newRefreshToken,
                "token_type",    "Bearer",
                "expires_in",    "900"
        ));
    }

    /**
     * Invalida o refresh_token (logout).
     *
     * POST /jwt/logout
     * Body: { "refresh_token": "<token>" }
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(@RequestBody Map<String, String> body) {
        String refreshToken = body.get("refresh_token");
        if (refreshToken != null) {
            refreshTokenService.revoke(refreshToken);
        }
        return ResponseEntity.ok(Map.of("message", "Logout realizado com sucesso"));
    }

    @GetMapping("/dashboard")
    public ResponseEntity<Map<String, Object>> dashboard(@AuthenticationPrincipal String username) {
        return ResponseEntity.ok(Map.of(
                "message",   "Área protegida por JWT",
                "loggedAs",  username
        ));
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> adminArea(@AuthenticationPrincipal String username) {
        return ResponseEntity.ok(Map.of(
                "message",  "Área exclusiva para administradores",
                "loggedAs", username
        ));
    }
}
