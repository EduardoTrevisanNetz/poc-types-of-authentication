package com.example.poctypesofauthentication.service;

import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RefreshTokenService {

    private final Set<String> validRefreshTokens = ConcurrentHashMap.newKeySet();

    public void store(String refreshToken) {
        validRefreshTokens.add(refreshToken);
    }

    public boolean isValid(String refreshToken) {
        return validRefreshTokens.contains(refreshToken);
    }

    public void revoke(String refreshToken) {
        validRefreshTokens.remove(refreshToken);
    }
}
