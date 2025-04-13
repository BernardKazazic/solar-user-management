package fer.solar.usermanagement.permission.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class PaginatedPermissionResponse {
    private List<PermissionResponse> content;
    private int currentPage;       // Currently always 0 as we fetch all at once
    private int pageSize;          // Number of items returned (total elements)
    private int totalPages;        // Currently always 1
    private long totalElements;    // Total number of permissions
} 