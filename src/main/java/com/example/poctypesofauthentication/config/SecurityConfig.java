package com.example.poctypesofauthentication.config;

import com.example.poctypesofauthentication.config.apikey.ApiKeyAuthFilter;
import com.example.poctypesofauthentication.config.jwt.JwtAuthFilter;
import com.example.poctypesofauthentication.service.UserDetailsServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
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

    private final UserDetailsServiceImpl userDetailsService;
    private final JwtAuthFilter jwtAuthFilter;
    private final ApiKeyAuthFilter apiKeyAuthFilter;

    // =========================================================
    // Beans compartilhados entre as chains
    // =========================================================

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    // =========================================================
    // Order 1 — BASIC AUTH  (/api/basic/**)
    // =========================================================

    /**
    simple de implementar porem tem que mandar toda vez usuario e senha
     haseado e tem que toda requisicao bater no banco...
     */
    @Bean
    @Order(1)
    public SecurityFilterChain basicAuthFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/api/basic/**")
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/basic/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated())
                /**
                aqui com http basic esta basicamente avisando ao spring para
                 que ele injete o filtro de basic auth, para quando chegar uma req
                 o proprio filtro ja cuida da implementacao e validacao da autenticacao
                 */
                .httpBasic(Customizer.withDefaults())
                .authenticationProvider(authenticationProvider());

        return http.build();
    }

    // =========================================================
    // Order 2 — JWT  (/api/jwt/**)
    // =========================================================

    /**
     */
    @Bean
    @Order(2)
    public SecurityFilterChain jwtFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/api/jwt/**")
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/jwt/auth/**").permitAll()
                        .requestMatchers("/api/jwt/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // =========================================================
    // Order 3 — OAUTH2  (/api/oauth2/**)
    // =========================================================

    /**
     */
    @Bean
    @Order(3)
    public SecurityFilterChain oauth2FilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/api/oauth2/**", "/login/oauth2/**", "/oauth2/**")
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/oauth2/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .oauth2Login(oauth2 -> oauth2
                        .defaultSuccessUrl("/api/oauth2/profile", true)
                        .failureUrl("/api/oauth2/error"));

        return http.build();
    }

    // =========================================================
    // Order 4 — FORM LOGIN  (/api/form/**)
    // =========================================================

    /**
     */
    @Bean
    @Order(4)
    public SecurityFilterChain formLoginFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/api/form/**", "/login", "/logout")
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login").permitAll()
                        .requestMatchers("/api/form/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .formLogin(form -> form
                        .loginPage("/login")
                        .defaultSuccessUrl("/api/form/dashboard", true)
                        .failureUrl("/login?error=true")
                        .permitAll())
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout=true")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID"))
                .authenticationProvider(authenticationProvider());

        return http.build();
    }

    // =========================================================
    // Order 5 — API KEY  (/api/apikey/**)
    // =========================================================

    /** */
    @Bean
    @Order(5)
    public SecurityFilterChain apiKeyFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/api/apikey/**")
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().hasRole("SERVICE"))
                .addFilterBefore(apiKeyAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // =========================================================
    // Order 6 — PÚBLICO  (/api/public/**)
    // =========================================================
    @Bean
    @Order(6)
    public SecurityFilterChain publicFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/api/public/**")
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());

        return http.build();
    }
}
