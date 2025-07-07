package io.github.akumosstl.gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

@Component
public class AuthBasic2JwtGatewayFilterFactory extends AbstractGatewayFilterFactory<AuthBasic2JwtGatewayFilterFactory.Config> {

    private final WebClient webClient;
    private final String tokenUri;
    private final String clientId;
    private final String clientSecret;

    public AuthBasic2JwtGatewayFilterFactory(WebClient.Builder webClientBuilder,
                                             @Value("${spring.security.oauth2.client.provider.custom.token-uri}") String tokenUri,
                                             @Value("${spring.security.oauth2.client.registration.custom.client-id}") String clientId,
                                             @Value("${spring.security.oauth2.client.registration.custom.client-secret}") String clientSecret) {
        super(Config.class);
        this.webClient = webClientBuilder
                .baseUrl(getBaseUrl(tokenUri)) // Extract base URL from token URI
                .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .build();
        this.tokenUri = getPath(tokenUri); // Extract path from token URI
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    private static String getBaseUrl(String uri) {
        int lastSlash = uri.lastIndexOf('/');
        if (lastSlash > 0 && (lastSlash + 1) < uri.length()) {
            // Handles cases like http://localhost:9000/oauth2/token
            int pathStart = uri.indexOf('/', uri.indexOf("://") + 3); // find first slash after "://"
            if (pathStart != -1) {
                return uri.substring(0, pathStart);
            }
        }
        // Fallback or error if URI format is unexpected
        return uri; // Or throw an exception
    }

    private static String getPath(String uri) {
        int firstSlashAfterHost = uri.indexOf('/', uri.indexOf("://") + 3);
        if (firstSlashAfterHost != -1) {
            return uri.substring(firstSlashAfterHost);
        }
        return "/"; // Fallback or error
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
                            .uri(this.tokenUri)
                            .headers(h -> h.setBasicAuth(this.clientId, this.clientSecret))
                            .bodyValue("grant_type=password&username=" + username + "&password=" + password + "&scope=openid")
                            .retrieve()
                            .bodyToMono(Map.class)
                            .flatMap(tokenResponse -> {
                                String accessToken = (String) tokenResponse.get("access_token");
                                if (accessToken == null) {
                                    // Handle error: token not found in response
                                    // For now, log and pass through, or return an error response
                                    System.err.println("Access token not found in password grant response");
                                    return chain.filter(exchange);
                                }
                                ServerHttpRequest mutatedRequest = request.mutate()
                                        .headers(httpHeaders -> {
                                            httpHeaders.remove(HttpHeaders.AUTHORIZATION);
                                            httpHeaders.setBearerAuth(accessToken);
                                        }).build();
                                return chain.filter(exchange.mutate().request(mutatedRequest).build());
                            })
                            .onErrorResume(e -> {
                                // Log error and pass through, or return an error response
                                System.err.println("Error during password grant token retrieval: " + e.getMessage());
                                return chain.filter(exchange); // Fallback on error
                            });
                }
            }

            // If no Authorization header, attempt client credentials grant
            if (!headers.containsKey(HttpHeaders.AUTHORIZATION)) {
                return webClient.post()
                        .uri(this.tokenUri)
                        .headers(h -> h.setBasicAuth(this.clientId, this.clientSecret))
                        .bodyValue("grant_type=client_credentials&scope=openid") // Assuming 'openid' scope is desired/needed
                        .retrieve()
                        .bodyToMono(Map.class)
                        .flatMap(tokenResponse -> {
                            String accessToken = (String) tokenResponse.get("access_token");
                            if (accessToken == null) {
                                // Handle error: token not found in response
                                System.err.println("Access token not found in client credentials grant response");
                                return chain.filter(exchange); // Fallback
                            }
                            ServerHttpRequest mutatedRequest = request.mutate()
                                    .headers(httpHeaders -> httpHeaders.setBearerAuth(accessToken))
                                    .build();
                            return chain.filter(exchange.mutate().request(mutatedRequest).build());
                        })
                        .onErrorResume(e -> {
                            // Log error and pass through, or return an error response
                            System.err.println("Error during client credentials token retrieval: " + e.getMessage());
                            return chain.filter(exchange); // Fallback on error
                        });
            }

            // Default fallback (e.g., if Auth header is present but not Basic or Bearer)
            return chain.filter(exchange);
        };
    }

    public static class Config {
        // Placeholder for future configuration if needed
    }
}
