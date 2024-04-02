package com.security.server.resource.authentication;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Collection;

public class CustomAuthentication extends JwtAuthenticationToken {
    private final String priority;

    // Создаем кастомный объект аутентификации
    public CustomAuthentication(
            Jwt jwt,
            Collection<? extends GrantedAuthority> authorities,
            String priority) {
        super(jwt, authorities);
        // Кастомное поле, передаваемое через access token
        this.priority = priority;
    }

    public String getPriority() {
        return priority;
    }
}