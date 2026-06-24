package com.example.poctypesofauthentication.config;

import com.example.poctypesofauthentication.filter.ApiKeyAuthFilter;
import com.example.poctypesofauthentication.filter.ApiKeyRateLimitFilter;
import com.example.poctypesofauthentication.filter.JwtAuthFilter;
import com.example.poctypesofauthentication.repository.ApiKeyRepository;
import com.example.poctypesofauthentication.service.JwtService;
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
public class SecurityConfig {

    // =========================================================
    // Order 1 — BASIC AUTH  (/http-basic/**)
    // =========================================================
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
    @Bean
    @Order(2)
    public SecurityFilterChain jwtFilterChain(HttpSecurity http, JwtService jwtService) throws Exception {
        return http
                .securityMatcher("/jwt/**")
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/jwt/login", "/jwt/refresh", "/jwt/logout").permitAll()
                        .anyRequest().authenticated())
                .addFilterBefore(new JwtAuthFilter(jwtService), UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    // =========================================================
    // Order 3 — API KEY  (/apikey/**)
    // =========================================================
    @Bean
    @Order(3)
    public SecurityFilterChain apiKeyFilterChain(HttpSecurity http, ApiKeyRepository apiKeyRepository) throws Exception {
        return http
                .securityMatcher("/apikey/**")
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated())
                .addFilterBefore(new ApiKeyRateLimitFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new ApiKeyAuthFilter(apiKeyRepository), ApiKeyRateLimitFilter.class)
                .build();
    }

    // =========================================================
    // Order 4 — SOCIAL LOGIN  (/social/**)
    // =========================================================
    @Bean
    @Order(4)
    public SecurityFilterChain socialLoginFilterChain(HttpSecurity http) throws Exception {
        return http
                .securityMatcher("/social/**", "/oauth2/authorization/**", "/login/oauth2/**")
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated())
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/oauth2/authorization/github")
                        .defaultSuccessUrl("/social/profile", true))
                .build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
