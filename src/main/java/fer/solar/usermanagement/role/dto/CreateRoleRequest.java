package fer.solar.usermanagement.role.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class CreateRoleRequest {
    private String name;
    private String description;
} 