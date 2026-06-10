package com.example.poctypesofauthentication.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor

public class UserModel {

    private Long id;
    private String username;
    private String password;
    private String role;
}
