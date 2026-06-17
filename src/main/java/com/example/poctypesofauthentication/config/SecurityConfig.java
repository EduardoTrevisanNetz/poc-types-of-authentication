package com.example.poctypesofauthentication.config;

import com.example.poctypesofauthentication.filter.ApiKeyAuthFilter;
import com.example.poctypesofauthentication.filter.JwtAuthFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;
    private final ApiKeyAuthFilter apiKeyAuthFilter;

    // =========================================================
    // Order 1 — BASIC AUTH  (/http-basic/**)
    // =========================================================
    /**
     * Simples de implementar, porém manda usuário e senha em toda requisição
     * e bate no banco a cada chamada.
     */
    @Bean
    @Order(1)
    public SecurityFilterChain basicAuthFilterChain(HttpSecurity http) throws Exception {
        return http
                .securityMatcher("/http-basic/**")
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/http-basic/**").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults())
                .build();
    }

    // =========================================================
    // Order 2 — JWT  (/jwt/**)
    // =========================================================
    /**
     * O que fazemos MANUALMENTE aqui vs oauth2ResourceServer().jwt():
     *
     *  MANUAL (nosso JwtAuthFilter)           | oauth2ResourceServer().jwt()
     * ----------------------------------------|----------------------------------------------
     *  JwtAuthFilter (OncePerRequestFilter)   | BearerTokenAuthenticationFilter (automático)
     *  JwtService.extractUsername()           | NimbusJwtDecoder.decode()       (automático)
     *  JwtService.isTokenValid()              | JwtAuthenticationProvider       (automático)
     *  Monta UsernamePasswordAuthToken manual | Monta JwtAuthenticationToken    (automático)
     *  Precisa de UserDetailsService          | Não precisa — lê claims do JWT  (automático)
     *
     * O endpoint POST /jwt/login (emitir token) NÃO existe no oauth2ResourceServer —
     * isso é papel do Authorization Server (ex: Keycloak, Spring Authorization Server).
     */
    @Bean
    @Order(2)
    public SecurityFilterChain jwtFilterChain(HttpSecurity http) throws Exception {
        return http
                .securityMatcher("/jwt/**")
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/jwt/login").permitAll()
                        .anyRequest().authenticated())
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

//    // =========================================================
//    // Order 3 — OAUTH2  (/oauth2/**)
//    // =========================================================
//    @Bean
//    @Order(3)
//    public SecurityFilterChain oauth2FilterChain(HttpSecurity http) throws Exception { ... }

    // =========================================================
    // Order 4 — API KEY  (/apikey/**)
    // =========================================================
    /**
     * Diferenças em relação ao JWT:
     *  - Não tem expiração — a chave vale até ser revogada
     *  - Não é auto-contida — precisa consultar o repositório a cada request (não é stateless puro)
     *  - Ideal para integrações B2B onde o cliente é uma máquina, não um usuário
     */
    @Bean
    @Order(4)
    public SecurityFilterChain apiKeyFilterChain(HttpSecurity http) throws Exception {
        return http
                .securityMatcher("/apikey/**")
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated())
                .addFilterBefore(apiKeyAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

//    // =========================================================
//    // Order 6 — PÚBLICO  (/public/**)
//    // =========================================================
//    @Bean
//    @Order(6)
//    public SecurityFilterChain publicFilterChain(HttpSecurity http) throws Exception { ... }

    /** Necessário para o JWTController autenticar username/password no /jwt/login */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
