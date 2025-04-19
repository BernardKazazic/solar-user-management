package fer.solar.usermanagement.user;

import fer.solar.usermanagement.user.dto.CreateUserRequest;
import fer.solar.usermanagement.user.dto.CreateUserResponse;
import fer.solar.usermanagement.user.dto.PaginatedUserResponse;
import fer.solar.usermanagement.user.dto.UserResponse;
import reactor.core.publisher.Mono;

public interface UserService {

    Mono<CreateUserResponse> createUser(CreateUserRequest request);

    Mono<PaginatedUserResponse> listUsers(int page, int size);

    Mono<UserResponse> getUserById(String userId);

    /**
     * TODO: Updates a user's details in Auth0 (implementation details TBD based on specific needs).
     *
     * @param userId The ID of the user to update.
     * @param request The request containing updated user details.
     * @return A Mono containing the updated UserResponse.
     */
    // Mono<UserResponse> updateUser(String userId, UpdateUserRequest request); // Assumes UpdateUserRequest in user.dto

    Mono<Void> deleteUser(String userId);
} 