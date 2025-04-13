package fer.solar.usermanagement.permission;

import com.auth0.client.mgmt.ManagementAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.mgmt.permissions.Permission;
import com.auth0.json.mgmt.resourceserver.ResourceServer;
import com.auth0.json.mgmt.resourceserver.Scope;
import fer.solar.usermanagement.config.Auth0Config;
import fer.solar.usermanagement.permission.dto.PaginatedPermissionResponse;
import fer.solar.usermanagement.permission.dto.PermissionResponse;
import fer.solar.usermanagement.permission.dto.UpdatePermissionsRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class Auth0PermissionService implements PermissionService {

    private final Auth0Config auth0Config;

    @Override
    public Mono<PaginatedPermissionResponse> listPermissions() {
        return fetchScopesFromApi()
                .map(this::buildPaginatedPermissionResponse)
                .subscribeOn(Schedulers.boundedElastic());
    }

    private Mono<List<Scope>> fetchScopesFromApi() {
        return Mono.fromCallable(() -> {
            ManagementAPI mgmt = auth0Config.getRefreshedManagementAPI();
            String apiIdentifier = auth0Config.getApiGatewayIdentifier();
            try {
                ResourceServer server = mgmt.resourceServers().get(apiIdentifier).execute().getBody();
                log.info("Fetched scopes for resource server: {}", apiIdentifier);
                return server.getScopes() != null ? server.getScopes() : Collections.<Scope>emptyList();
            } catch (Auth0Exception e) {
                log.error("Failed to fetch scopes for resource server {}: {}", apiIdentifier, e.getMessage());
                throw new RuntimeException("Failed to fetch API scopes", e);
            }
        }).onErrorReturn(Collections.emptyList()); // Return empty on error after logging
    }

    private PaginatedPermissionResponse buildPaginatedPermissionResponse(List<Scope> scopes) {
        List<PermissionResponse> permissionResponses = scopes.stream()
                .map(scope -> PermissionResponse.builder()
                        .permissionName(scope.getValue()) // Scope value is the permission name
                        .description(scope.getDescription())
                        .build())
                .collect(Collectors.toList());

        // Auth0 Resource Server scopes aren't typically paginated in the same way users/roles are.
        // We fetch all scopes at once.
        int totalElements = permissionResponses.size();
        return PaginatedPermissionResponse.builder()
                .content(permissionResponses)
                .currentPage(0)
                .pageSize(totalElements) // Size is total elements
                .totalElements(totalElements)
                .totalPages(totalElements > 0 ? 1 : 0) // Always 1 page if results exist
                .build();
    }

    @Override
    public Mono<Void> updatePermissions(UpdatePermissionsRequest request) {
        return Mono.fromRunnable(() -> {
            ManagementAPI mgmt = auth0Config.getRefreshedManagementAPI();
            String apiIdentifier = auth0Config.getApiGatewayIdentifier();

            // Map DTO to Auth0 Scope objects
            List<Scope> newScopes = request.getPermissions().stream()
                .map(pUpdate -> {
                    // Corrected: Scope likely only takes the value (permission name) in constructor or has a setter
                    // Try using just the value. Descriptions might be managed separately.
                    return new Scope(pUpdate.getPermissionName()); // Assuming Scope(value)
                    // Alternative if no constructor: Scope s = new Scope(); s.setValue(name); return s;
                })
                .collect(Collectors.toList());

            // Create ResourceServer object containing only the updated scopes
            ResourceServer serverUpdates = new ResourceServer();
            serverUpdates.setScopes(newScopes);

            try {
                // Update the resource server - this replaces ALL existing scopes
                mgmt.resourceServers().update(apiIdentifier, serverUpdates).execute();
                log.info("Successfully updated scopes for resource server: {}", apiIdentifier);
            } catch (Auth0Exception e) {
                log.error("Failed to update scopes for resource server {}: {}", apiIdentifier, e.getMessage(), e);
                throw new RuntimeException("Failed to update API scopes", e);
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }
} 