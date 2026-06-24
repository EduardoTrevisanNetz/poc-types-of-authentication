package com.example.poctypesofauthentication.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class JwtService {

    private static final String SECRET = "SECRET-SUPER-SECRETAMENTE-SECRETA-DA-SILVA";

    private static final long ACCESS_TOKEN_EXPIRATION_MS = 1000L * 60 * 15;
    private static final long REFRESH_TOKEN_EXPIRATION_MS = 1000L * 60 * 60 * 24 * 7;

    public String generateAccessToken(UserDetails userDetails) {
        return buildToken(userDetails, ACCESS_TOKEN_EXPIRATION_MS, "access");
    }

    public String generateRefreshToken(UserDetails userDetails) {
        return buildToken(userDetails, REFRESH_TOKEN_EXPIRATION_MS, "refresh");
    }

    private String buildToken(UserDetails userDetails, long expirationMs, String tokenType) {
        return Jwts.builder()
                .subject(userDetails.getUsername())
                .claim("roles", userDetails.getAuthorities().stream()
                        .map(a -> a.getAuthority()).toList())
                .claim("type", tokenType)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(getSigningKey())
                .compact();
    }

    public String extractUsername(String token) {
        return parseClaims(token).getSubject();
    }

    public List<GrantedAuthority> extractAuthorities(String token) {
        List<String> roles = parseClaims(token).get("roles", List.class);
        if (roles == null) return List.of();
        return roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    public boolean isAccessToken(String token) {
        return "access".equals(parseClaims(token).get("type", String.class));
    }

    public boolean isRefreshToken(String token) {
        return "refresh".equals(parseClaims(token).get("type", String.class));
    }

    public boolean isTokenExpired(String token) {
        return parseClaims(token).getExpiration().before(new Date());
    }

    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
    }
}
