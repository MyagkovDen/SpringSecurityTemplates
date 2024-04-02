package com.security.server.resource.authentication;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class JwtAuthenticationConverter implements Converter<Jwt, CustomAuthentication> {

    // Объект конвертера будет принимать токен и возвращать кастомную аутентификацию
    @Override
    public CustomAuthentication convert(Jwt source) {
        // В реальном сценарии authorities тоже берутся из access token
        // (если устанавливаются на сервере авторизации), либо из БД
        List<GrantedAuthority> authorities = List.of(() -> "read");
        String priority = String.valueOf(source.getClaims().get("priority"));
        return new CustomAuthentication(source,
                authorities,
                priority);
    }
}
