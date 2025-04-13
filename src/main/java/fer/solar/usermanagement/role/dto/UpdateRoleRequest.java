package fer.solar.usermanagement.role.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
public class UpdateRoleRequest {
    private String name;
    private String description;
    private List<String> permissionIds;
} 