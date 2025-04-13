package fer.solar.usermanagement.role.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class RoleResponse {
    private String id;
    private String name;
    private String description;
    private List<String> permissions; // List of permission names associated with the role
} 