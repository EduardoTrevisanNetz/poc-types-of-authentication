package com.example.poctypesofauthentication.repository;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Repository;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Repository
public class ApiKeyRepository {

    private final Map<String, UserDetails> keys = new HashMap<>();

    public ApiKeyRepository() {
        keys.put("key-admin-123", User.builder()
                .username("admin-service")
                .password("")
                .authorities(List.of(new SimpleGrantedAuthority("ROLE_ADMIN")))
                .build());

        keys.put("key-user-456", User.builder()
                .username("user-service")
                .password("")
                .authorities(List.of(new SimpleGrantedAuthority("ROLE_USER")))
                .build());
    }

    public Optional<UserDetails> findByKey(String apiKey) {
        return Optional.ofNullable(keys.get(apiKey));
    }
}
