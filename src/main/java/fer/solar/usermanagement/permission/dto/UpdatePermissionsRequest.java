package fer.solar.usermanagement.permission.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
public class UpdatePermissionsRequest {
    private List<PermissionUpdate> permissions;

    @Data
    @NoArgsConstructor
    public static class PermissionUpdate {
        private String permissionName; // The scope value, e.g., "read:users"
        private String description;    // The scope description
    }
} 