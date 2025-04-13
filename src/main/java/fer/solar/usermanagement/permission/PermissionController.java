package fer.solar.usermanagement.permission;

import fer.solar.usermanagement.permission.dto.PaginatedPermissionResponse;
import fer.solar.usermanagement.permission.dto.UpdatePermissionsRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/v1/permissions")
@RequiredArgsConstructor
public class PermissionController {

    private final PermissionService permissionService;

    @GetMapping
    public Mono<PaginatedPermissionResponse> listPermissions() {
        // Currently fetches all permissions, pagination is handled in the response DTO structure
        return permissionService.listPermissions();
    }

    @PutMapping
    @ResponseStatus(HttpStatus.NO_CONTENT) // Or OK if returning the updated list
    public Mono<Void> updatePermissions(@RequestBody UpdatePermissionsRequest request) {
        return permissionService.updatePermissions(request);
    }

    // Note: Creating/Deleting individual permissions (scopes) is done via the PUT endpoint
    // by providing the complete desired list of scopes for the resource server.
    // Auth0 doesn't typically have separate POST/DELETE endpoints for individual scopes
    // within a resource server's definition via the Management API.
} 