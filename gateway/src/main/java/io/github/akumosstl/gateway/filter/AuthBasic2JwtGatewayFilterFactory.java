package io.github.akumosstl.gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

@Component
public class AuthBasic2JwtGatewayFilterFactory extends AbstractGatewayFilterFactory<AuthBasic2JwtGatewayFilterFactory.Config> {

    private final WebClient webClient;

    public AuthBasic2JwtGatewayFilterFactory() {
        super(Config.class);
        this.webClient = WebClient.builder()
                .baseUrl("http://localhost:9000") // Your Auth Server
                .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .build();
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            HttpHeaders headers = request.getHeaders();

            // Skip if Bearer token is already present
            if (headers.containsKey(HttpHeaders.AUTHORIZATION) &&
                    headers.getFirst(HttpHeaders.AUTHORIZATION).startsWith("Bearer ")) {
                return chain.filter(exchange);
            }

            // Handle Basic Auth
            if (headers.containsKey(HttpHeaders.AUTHORIZATION) &&
                    headers.getFirst(HttpHeaders.AUTHORIZATION).startsWith("Basic ")) {

                String base64Credentials = headers.getFirst(HttpHeaders.AUTHORIZATION).substring("Basic ".length());
                byte[] decodedBytes = Base64.getDecoder().decode(base64Credentials);
                String decoded = new String(decodedBytes, StandardCharsets.UTF_8);
                String[] parts = decoded.split(":", 2);

                if (parts.length == 2) {
                    String username = parts[0];
                    String password = parts[1];

                    // Call OAuth2 Token Endpoint with password grant
                    return webClient.post()
                            .uri("/oauth2/token")
                            .headers(h -> h.setBasicAuth("client-id", "client-secret")) // your OAuth2 client credentials
                            .bodyValue("grant_type=password&username=" + username + "&password=" + password)
                            .retrieve()
                            .bodyToMono(Map.class)
                            .flatMap(tokenResponse -> {
                                String accessToken = (String) tokenResponse.get("access_token");

                                // Inject Bearer token into request
                                ServerHttpRequest mutatedRequest = request.mutate()
                                        .headers(httpHeaders -> {
                                            httpHeaders.remove(HttpHeaders.AUTHORIZATION);
                                            httpHeaders.setBearerAuth(accessToken);
                                        }).build();

                                return chain.filter(exchange.mutate().request(mutatedRequest).build());
                            });
                }
            }

            // Default fallback: continue without mutation
            return chain.filter(exchange);
        };
    }

    public static class Config {
        // Placeholder for future configuration if needed
    }
}
