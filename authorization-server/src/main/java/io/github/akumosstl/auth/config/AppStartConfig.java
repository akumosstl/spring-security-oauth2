package io.github.akumosstl.auth.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Base64;

@Configuration
public class AppStartConfig {

    @Bean
    public CommandLineRunner printBasicAuthHeader() {
        return args -> {
            String username = "user";
            String password = "password";
            String plainCredentials = username + ":" + password;
            String base64Credentials = Base64.getEncoder().encodeToString(plainCredentials.getBytes());
            System.out.println("🔐 Basic Auth Header:");
            System.out.println("Authorization: Basic " + base64Credentials);
        };
    }
}

