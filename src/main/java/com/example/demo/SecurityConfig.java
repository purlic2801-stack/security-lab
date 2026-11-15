package com.example.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final VulnerabilityState state;

    public SecurityConfig(VulnerabilityState state) {
        this.state = state;
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        RequestMatcher csrfMeta = request ->
            !state.isCsrfVulnerable()
            && "POST".equalsIgnoreCase(request.getMethod())
            && "/preferences/notifications".equals(request.getRequestURI());

        http
            .authorizeHttpRequests(a -> a.anyRequest().permitAll())
            .csrf(csrf -> csrf.requireCsrfProtectionMatcher(csrfMeta))
            .headers(h -> h.frameOptions(f -> f.sameOrigin()));

        return http.build();
    }
}