package com.example.poctypesofauthentication.repository;

import com.example.poctypesofauthentication.model.User;
import com.example.poctypesofauthentication.model.UserModel;
import org.springframework.stereotype.Repository;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Repositório in-memory para fins de demonstração do Basic Auth.
 * Em produção, utilize um banco de dados real (ex: JPA + PostgreSQL).
 */
@Repository
public class UserRepository {

    private final Map<String, User> users = new HashMap<>();

    public UserRepository() {
        users.put("admin", User.builder()
                .id(1L)
                .username("admin")
                .password("admin123")
                .role("ADMIN")
                .build());

        users.put("user", User.builder()
                .id(2L)
                .username("user")
                .password("user123")
                .role("USER")
                .build());
    }

    public Optional<UserModel> findByUsername(String username) {
        return Optional.ofNullable(users.get(username));
    }
}
