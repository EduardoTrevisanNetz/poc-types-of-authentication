package com.example.poctypesofauthentication.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
public class ApiKeyRateLimitFilter extends OncePerRequestFilter {

    private static final int MAX_REQUESTS_PER_WINDOW = 10;
    private static final long WINDOW_SIZE_MS = 60_000L;

    private record WindowCounter(AtomicInteger count, Instant windowStart) {}

    private final ConcurrentHashMap<String, WindowCounter> counters = new ConcurrentHashMap<>();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String apiKey = request.getHeader(ApiKeyAuthFilter.API_KEY_HEADER);

        if (apiKey == null) {
            filterChain.doFilter(request, response);
            return;
        }

        WindowCounter window = counters.compute(apiKey, (key, existing) -> {
            Instant now = Instant.now();
            if (existing == null || now.toEpochMilli() - existing.windowStart().toEpochMilli() >= WINDOW_SIZE_MS) {
                return new WindowCounter(new AtomicInteger(1), now);
            }
            existing.count().incrementAndGet();
            return existing;
        });

        int currentCount = window.count().get();

        response.setHeader("X-RateLimit-Limit",     String.valueOf(MAX_REQUESTS_PER_WINDOW));
        response.setHeader("X-RateLimit-Remaining", String.valueOf(Math.max(0, MAX_REQUESTS_PER_WINDOW - currentCount)));

        if (currentCount > MAX_REQUESTS_PER_WINDOW) {
            response.setStatus(429);
            response.setContentType("application/json");
            response.getWriter().write("""
                    {"error": "Too Many Requests", "message": "Limite de %d requisições/minuto excedido. Tente novamente em instantes."}
                    """.formatted(MAX_REQUESTS_PER_WINDOW));
            return;
        }

        filterChain.doFilter(request, response);
    }
}
