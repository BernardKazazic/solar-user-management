package fer.solar.usermanagement.role;

import fer.solar.usermanagement.role.dto.*;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/v1/roles")
@RequiredArgsConstructor
public class RoleController {

    private final RoleService roleService;

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<RoleResponse> createRole(@RequestBody CreateRoleRequest createRoleRequest) {
        return roleService.createRole(createRoleRequest);
    }

    @GetMapping
    public Mono<PaginatedRoleResponse> listRoles(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size
    ) {
        if (size < 1) {
            size = 20;
        }
        if (page < 0) {
            page = 0;
        }
        return roleService.listRoles(page, size);
    }

    @GetMapping("/{roleId}")
    public Mono<ResponseEntity<RoleResponse>> getRoleById(@PathVariable String roleId) {
        return roleService.getRoleById(roleId)
                .map(ResponseEntity::ok)
                .defaultIfEmpty(ResponseEntity.notFound().build());
    }

    @PutMapping("/{roleId}")
    public Mono<ResponseEntity<RoleResponse>> updateRole(@PathVariable String roleId, @RequestBody UpdateRoleRequest updateRoleRequest) {
        return roleService.updateRole(roleId, updateRoleRequest)
                .map(ResponseEntity::ok)
                .defaultIfEmpty(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{roleId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> deleteRole(@PathVariable String roleId) {
        return roleService.deleteRole(roleId);
    }
} 