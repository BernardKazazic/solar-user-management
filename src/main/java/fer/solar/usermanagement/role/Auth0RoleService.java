package fer.solar.usermanagement.role;

import com.auth0.client.mgmt.ManagementAPI;
import com.auth0.client.mgmt.filter.PageFilter;
import com.auth0.client.mgmt.filter.RolesFilter;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.mgmt.permissions.PermissionsPage;
import com.auth0.json.mgmt.roles.RolesPage;
import com.auth0.json.mgmt.permissions.Permission;
import com.auth0.json.mgmt.roles.Role;
import com.auth0.json.mgmt.resourceserver.Scope;
import fer.solar.usermanagement.config.Auth0Config;
import fer.solar.usermanagement.role.dto.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class Auth0RoleService implements RoleService {

    private final Auth0Config auth0Config;

    @Override
    public Mono<RoleResponse> createRole(CreateRoleRequest request) {
        return Mono.fromCallable(() -> {
                    ManagementAPI mgmt = auth0Config.getRefreshedManagementAPI();
                    Role newRole = new Role();
                    newRole.setName(request.getName());
                    newRole.setDescription(request.getDescription());
                    try {
                        Role createdRole = mgmt.roles().create(newRole).execute().getBody();
                        log.info("Created Auth0 role: {}", createdRole.getId());
                        // Permissions must be added via the update endpoint.
                        // Use getRoleById to ensure consistent response structure including permissions (empty initially)
                        return getRoleById(createdRole.getId()).block(); // Blocking acceptable in fromCallable on boundedElastic
                    } catch (Auth0Exception e) {
                        log.error("Error creating Auth0 role with name {}: {}", request.getName(), e.getMessage(), e);
                        throw new RuntimeException("Failed to create role in Auth0", e);
                    }
                })
                .subscribeOn(Schedulers.boundedElastic());
    }

    @Override
    public Mono<PaginatedRoleResponse> listRoles(int page, int size) {
        return fetchRolesPageFromAuth0(page, size)
                .flatMap(this::buildPaginatedRoleResponse)
                .subscribeOn(Schedulers.boundedElastic());
    }

    private Mono<RolesPage> fetchRolesPageFromAuth0(int page, int size) {
        return Mono.fromCallable(() -> {
            ManagementAPI mgmt = auth0Config.getRefreshedManagementAPI();
            RolesFilter filter = new RolesFilter().withPage(page, size).withTotals(true);
            try {
                return mgmt.roles().list(filter).execute().getBody();
            } catch (Auth0Exception e) {
                log.error("Error fetching roles page from Auth0 (page={}, size={}): {}", page, size, e.getMessage(), e);
                throw new RuntimeException("Failed to list roles from Auth0", e);
            }
        });
    }

    private Mono<PaginatedRoleResponse> buildPaginatedRoleResponse(RolesPage rolesPage) {
        Flux<RoleResponse> roleResponseFlux = Flux.fromIterable(rolesPage.getItems())
                .flatMap(role -> fetchPermissionsForRole(role.getId())
                        .flatMap(permissions -> mapRoleToResponse(role, permissions)));

        return roleResponseFlux.collectList().map(roleResponses -> {
            long totalElements = rolesPage.getTotal();
            int pageSize = rolesPage.getLimit() != null ? rolesPage.getLimit() : (roleResponses.isEmpty() ? 0 : roleResponses.size());
            int currentPage = rolesPage.getStart() != null ? rolesPage.getStart() / Math.max(1, pageSize) : 0;
            int totalPages = (pageSize > 0) ? (int) Math.ceil((double) totalElements / pageSize) : (totalElements > 0 ? 1 : 0);

            return PaginatedRoleResponse.builder()
                    .content(roleResponses)
                    .currentPage(currentPage)
                    .pageSize(pageSize)
                    .totalElements(totalElements)
                    .totalPages(totalPages)
                    .build();
        });
    }

    private Mono<List<Permission>> fetchPermissionsForRole(String roleId) {
        return Mono.fromCallable(() -> {
                    ManagementAPI mgmt = auth0Config.getRefreshedManagementAPI();
                    PageFilter filter = new PageFilter();
                    try {
                        PermissionsPage page = mgmt.roles().listPermissions(roleId, filter).execute().getBody();
                        // Ensure items are not null before returning
                        return page.getItems() != null ? page.getItems() : Collections.<Permission>emptyList();
                    } catch (Auth0Exception e) {
                        log.error("Error fetching permissions for role {}: {}", roleId, e.getMessage());
                        throw new RuntimeException("Failed to fetch permissions for role " + roleId, e);
                    }
                })
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorReturn(Collections.emptyList());
    }

    private Mono<RoleResponse> mapRoleToResponse(Role role, List<Permission> permissions) {
        List<String> permissionNames = permissions != null ?
                permissions.stream().map(Permission::getName).collect(Collectors.toList()) :
                Collections.emptyList();

        return Mono.just(RoleResponse.builder()
                .id(role.getId())
                .name(role.getName())
                .description(role.getDescription())
                .permissions(permissionNames)
                .build());
    }

    @Override
    public Mono<RoleResponse> getRoleById(String roleId) {
        return Mono.fromCallable(() -> {
                    ManagementAPI mgmt = auth0Config.getRefreshedManagementAPI();
                    return mgmt.roles().get(roleId).execute().getBody();
                })
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(role -> fetchPermissionsForRole(roleId)
                    .flatMap(permissions -> mapRoleToResponse(role, permissions))
                )
                .onErrorMap(Auth0Exception.class, e -> new RuntimeException("Failed to get role " + roleId, e));
    }

    @Override
    public Mono<RoleResponse> updateRole(String roleId, UpdateRoleRequest request) {
        Mono<Role> updateDetailsMono = Mono.fromCallable(() -> {
                    ManagementAPI mgmt = auth0Config.getRefreshedManagementAPI();
                    Role roleUpdates = new Role();
                    if (request.getName() != null) {
                        roleUpdates.setName(request.getName());
                    }
                    if (request.getDescription() != null) {
                        roleUpdates.setDescription(request.getDescription());
                    }
                    if (request.getName() == null && request.getDescription() == null) {
                        return mgmt.roles().get(roleId).execute().getBody();
                    }
                    Role updatedRole = mgmt.roles().update(roleId, roleUpdates).execute().getBody();
                    log.info("Updated Auth0 role base details: {}", roleId);
                    return updatedRole;
                })
                .subscribeOn(Schedulers.boundedElastic());

        Mono<Void> updatePermissionsMono = Mono.defer(() -> {
            if (request.getPermissionIds() != null) {
                return assignPermissionsToRole(roleId, request.getPermissionIds());
            } else {
                return Mono.empty();
            }
        });

        return updateDetailsMono
                .flatMap(updatedRole -> updatePermissionsMono.thenReturn(updatedRole.getId()))
                .flatMap(this::getRoleById)
                .doOnError(e -> log.error("Error updating Auth0 role {}: {}", roleId, e.getMessage(), e))
                .onErrorMap(Auth0Exception.class, e -> new RuntimeException("Failed to update role in Auth0", e));
    }

    private Mono<Void> assignPermissionsToRole(String roleId, List<String> permissionNames) {
        return fetchAllScopesForApi()
                .flatMap(apiScopes -> {
                    List<Scope> scopesToProcess = apiScopes.stream()
                            .filter(scope -> permissionNames.contains(scope.getValue()))
                            .collect(Collectors.toList());

                    List<Permission> permissionsToAssign = scopesToProcess.stream()
                            .map(scope -> {
                                Permission p = new Permission();
                                p.setName(scope.getValue());
                                p.setResourceServerId(auth0Config.getApiGatewayIdentifier());
                                return p;
                            })
                            .collect(Collectors.toList());

                    if (permissionsToAssign.size() != permissionNames.size()) {
                        List<String> foundNames = permissionsToAssign.stream().map(Permission::getName).collect(Collectors.toList());
                        log.warn("Role {}: Some requested permission names were not found in the API scopes: Requested={}, Found={}",
                                roleId, permissionNames, foundNames);
                    }

                    return Mono.fromRunnable(() -> {
                                ManagementAPI mgmt = auth0Config.getRefreshedManagementAPI();
                                try {
                                    mgmt.roles().addPermissions(roleId, permissionsToAssign).execute();
                                    log.info("Successfully set permissions {} for role {}",
                                            // Corrected: Use getName() in the log message stream
                                            permissionsToAssign.stream().map(Permission::getName).collect(Collectors.toList()), roleId);
                                } catch (Auth0Exception e) {
                                    log.error("Failed to assign permissions {} to role {}: {}", permissionNames, roleId, e.getMessage());
                                    throw new RuntimeException("Failed to assign permissions", e);
                                }
                            })
                            .subscribeOn(Schedulers.boundedElastic())
                            .then();
                });
    }

    private Mono<List<Scope>> fetchAllScopesForApi() {
        return Mono.fromCallable(() -> {
            ManagementAPI mgmt = auth0Config.getRefreshedManagementAPI();
            String apiIdentifier = auth0Config.getApiGatewayIdentifier();
            try {
                return mgmt.resourceServers().get(apiIdentifier).execute().getBody().getScopes();
            } catch (Auth0Exception e) {
                 log.error("Failed to fetch scopes for resource server {}: {}", apiIdentifier, e.getMessage());
                 throw new RuntimeException("Failed to fetch API scopes", e);
            }
        }).subscribeOn(Schedulers.boundedElastic());
    }

    @Override
    public Mono<Void> deleteRole(String roleId) {
        return Mono.fromRunnable(() -> {
                    try {
                        ManagementAPI mgmt = auth0Config.getRefreshedManagementAPI();
                        mgmt.roles().delete(roleId).execute();
                        log.info("Deleted Auth0 role with ID: {}", roleId);
                    } catch (Auth0Exception e) {
                        log.error("Error deleting Auth0 role with ID {}: {}", roleId, e.getMessage(), e);
                        throw new RuntimeException("Failed to delete role in Auth0", e);
                    }
                })
                .subscribeOn(Schedulers.boundedElastic())
                .then();
    }
} 