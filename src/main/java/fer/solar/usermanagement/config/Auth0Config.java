package fer.solar.usermanagement.config;

import com.auth0.client.auth.AuthAPI;
import com.auth0.client.mgmt.ManagementAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.TokenHolder;
import com.auth0.net.client.Auth0HttpClient;
import com.auth0.net.client.DefaultHttpClient;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.context.annotation.Profile;

@Configuration
@EnableScheduling
@Slf4j
@Getter
public class Auth0Config {

    @Value("${auth0.domain}")
    private String domain;

    @Value("${auth0.management.clientId}")
    private String clientId;

    @Value("${auth0.management.clientSecret}")
    private String clientSecret;

    @Value("${auth0.management.apiAudience}")
    private String apiAudience;

    @Value("${auth0.api-gateway-identifier}")
    private String apiGatewayIdentifier;

    private volatile TokenHolder tokenHolder;

    private final Auth0HttpClient httpClient = DefaultHttpClient.newBuilder().build();

    @Bean
    public AuthAPI authAPI() {
        return AuthAPI.newBuilder(domain, clientId, clientSecret)
                .withHttpClient(httpClient)
                .build();
    }

    @Bean
    public ManagementAPI managementAPI(AuthAPI authAPI) throws Auth0Exception {
        this.tokenHolder = fetchManagementApiToken(authAPI);
        log.info("Initial Auth0 Management API token obtained.");
        return ManagementAPI.newBuilder(domain, tokenHolder.getAccessToken())
                .withHttpClient(httpClient)
                .build();
    }

    @Scheduled(fixedRate = 6 * 60 * 60 * 1000) // Refresh every 20 hours
    public void refreshManagementApiToken() {
        try {
            AuthAPI auth = authAPI();
            this.tokenHolder = fetchManagementApiToken(auth);
            log.info("Auth0 Management API token refreshed successfully.");
        } catch (Auth0Exception e) {
            log.error("Error refreshing Auth0 Management API token: {}", e.getMessage(), e);
        }
    }

    private TokenHolder fetchManagementApiToken(AuthAPI authAPI) throws Auth0Exception {
        return authAPI.requestToken(apiAudience).execute().getBody();
    }

    public TokenHolder getCurrentTokenHolder() {
        return tokenHolder;
    }

    public ManagementAPI getRefreshedManagementAPI() {
        TokenHolder currentToken = getCurrentTokenHolder();
        if (currentToken == null || currentToken.getAccessToken() == null) {
            log.error("Cannot create ManagementAPI client: current token is null or invalid.");
            throw new IllegalStateException("Auth0 token is not available.");
        }
        return ManagementAPI.newBuilder(domain, currentToken.getAccessToken())
                    .withHttpClient(httpClient)
                    .build();
    }
} 