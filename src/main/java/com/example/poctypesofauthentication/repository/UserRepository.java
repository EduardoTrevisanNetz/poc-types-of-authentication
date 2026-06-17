package com.example.poctypesofauthentication.repository;

import com.example.poctypesofauthentication.model.UserModel;
import org.springframework.stereotype.Repository;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Repository
public class UserRepository {
    private final Map<String, UserModel> users = new HashMap<>();

    public UserRepository() {
        users.put("admin", UserModel.builder()
                .id(1L)
                .username("admin")
                .password("$2a$10$I5bZOT.zk3j/ZOhugcBVYOIxWgB7v6R8DQERoHtTxaYmAzi9xx.Ia")
                .role("ADMIN")
                .build());

        users.put("user", UserModel.builder()
                .id(2L)
                .username("user")
                .password("$2a$10$d/8YY7IrMoZhKr.3BeEy1OS0/fmWUf5hHsVF6vVAQCnueYT5IR9TG")
                .role("USER")
                .build());
    }

    public Optional<UserModel> findByUsername(String username) {
        return Optional.ofNullable(users.get(username));
    }
}
