package fer.solar.usermanagement.permission;

import fer.solar.usermanagement.permission.dto.PaginatedPermissionResponse;
import fer.solar.usermanagement.permission.dto.UpdatePermissionsRequest;
import reactor.core.publisher.Mono;

public interface PermissionService {
    Mono<PaginatedPermissionResponse> listPermissions();
    Mono<Void> updatePermissions(UpdatePermissionsRequest request);
} 