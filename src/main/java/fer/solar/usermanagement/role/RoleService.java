package fer.solar.usermanagement.role;

import fer.solar.usermanagement.role.dto.*;
import reactor.core.publisher.Mono;

public interface RoleService {
    Mono<RoleResponse> createRole(CreateRoleRequest request);
    Mono<PaginatedRoleResponse> listRoles(int page, int size);
    Mono<RoleResponse> getRoleById(String roleId);
    Mono<RoleResponse> updateRole(String roleId, UpdateRoleRequest request);
    Mono<Void> deleteRole(String roleId);
} 