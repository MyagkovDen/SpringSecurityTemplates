package com.security.server.resource.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class ProjectConfig {
    // Эндпойнт сервера авторизации, возвращающий набор публичных ключей ("jwks_uri") для валидации токенов
    @Value("${keySetURI}")
    private String keySetUri;

    // Конфигурация аутентификации с JWT-токенами
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http)
            throws Exception {
        // Установим JWT-аутентификацию
        http.oauth2ResourceServer(
                c -> c.jwt(
                        j -> j.jwkSetUri(keySetUri)
                )
        );
        // Установим доступ к эндпойнтам только для аутентифицированных пользователей
        http.authorizeHttpRequests(
                c -> c.anyRequest().authenticated()
        );
        return http.build();
    }
}