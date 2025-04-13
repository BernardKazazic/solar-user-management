package fer.solar.usermanagement.role.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class PaginatedRoleResponse {
    private List<RoleResponse> content;
    private int currentPage;
    private int pageSize;
    private int totalPages;
    private long totalElements;
} 