package com.example.poctypesofauthentication.service;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RefreshTokenService {

    private static final long EXPIRATION_MS = 1000L * 60 * 60 * 24 * 7; // 7 dias

    private record TokenEntry(String username, Instant expiresAt) {}

    private final ConcurrentHashMap<String, TokenEntry> store = new ConcurrentHashMap<>();

    public String generate(String username) {
        String token = UUID.randomUUID().toString();
        store.put(token, new TokenEntry(username, Instant.now().plusMillis(EXPIRATION_MS)));
        return token;
    }

    public boolean isValid(String token) {
        TokenEntry entry = store.get(token);
        return entry != null && Instant.now().isBefore(entry.expiresAt());
    }

    public String extractUsername(String token) {
        TokenEntry entry = store.get(token);
        if (entry == null) throw new IllegalArgumentException("Refresh token não encontrado");
        return entry.username();
    }

    public void revoke(String token) {
        store.remove(token);
    }
}
