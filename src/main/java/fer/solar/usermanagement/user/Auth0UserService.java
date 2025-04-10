package fer.solar.usermanagement.user;

import com.auth0.client.mgmt.ManagementAPI;
import com.auth0.client.mgmt.filter.UserFilter;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.mgmt.roles.Role;
import com.auth0.json.mgmt.tickets.PasswordChangeTicket;
import com.auth0.json.mgmt.users.User;
import com.auth0.json.mgmt.users.UsersPage;
import fer.solar.usermanagement.config.Auth0Config;
import fer.solar.usermanagement.user.dto.CreateUserRequest;
import fer.solar.usermanagement.user.dto.PaginatedUserResponse;
import fer.solar.usermanagement.user.dto.UserResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
@Profile("!test")
public class Auth0UserService implements UserService {

    private final Auth0Config auth0Config;

    @Override
    public Mono<String> createUser(CreateUserRequest request) {
        return Mono.fromCallable(() -> {
            User createdUser = null;
            try {
                createdUser = createAuth0User(request);
                assignRolesToUser(createdUser, request.getRoleIds());
                return generatePasswordChangeTicket(createdUser, request.getResultUrl());
            } catch (Auth0Exception e) {
                log.error("Error during user creation flow for email {}: {}", request.getEmail(), e.getMessage(), e);
                if (createdUser != null) {
                    attemptUserDeletionRollback(createdUser.getId());
                }
                throw new RuntimeException("Failed to complete user creation process: " + e.getMessage(), e);
            }
        }).subscribeOn(Schedulers.boundedElastic());
    }

    private User createAuth0User(CreateUserRequest request) throws Auth0Exception {
        ManagementAPI mgmt = auth0Config.getRefreshedManagementAPI();
        User newUser = new User(request.getConnection());
        newUser.setEmail(request.getEmail());
        newUser.setEmailVerified(false); // Explicitly false, ticket handles verification if needed

        char[] temporaryPassword = generateRandomPasswordChars(16);
        newUser.setPassword(temporaryPassword);
        // Ensure password is cleared from memory immediately after use for security
        java.util.Arrays.fill(temporaryPassword, '\0');

        try {
            User createdUser = mgmt.users().create(newUser).execute().getBody();
            log.info("Auth0 user created successfully with ID: {}", createdUser.getId());
            return createdUser;
        } catch (Auth0Exception e) {
            log.error("Failed to create Auth0 user for email {}: {}", request.getEmail(), e.getMessage());
            throw e;
        }
    }

    private void assignRolesToUser(User user, List<String> roleIds) throws Auth0Exception {
        if (roleIds == null || roleIds.isEmpty()) {
            log.debug("No roles specified for user {}, skipping role assignment.", user.getId());
            return;
        }

        ManagementAPI mgmt = auth0Config.getRefreshedManagementAPI();
        try {
            mgmt.users().addRoles(user.getId(), roleIds).execute();
            log.info("Successfully assigned roles {} to user {}", roleIds, user.getId());
        } catch (Auth0Exception e) {
            log.error("Failed to assign roles {} to user {}: {}", roleIds, user.getId(), e.getMessage());
            throw e;
        }
    }

    private String generatePasswordChangeTicket(User user, String resultUrl) throws Auth0Exception {
        ManagementAPI mgmt = auth0Config.getRefreshedManagementAPI();
        PasswordChangeTicket ticketRequest = new PasswordChangeTicket(user.getId());
        ticketRequest.setResultUrl(resultUrl);
        ticketRequest.setMarkEmailAsVerified(false); // Configurable: false means user verifies via password change
        ticketRequest.setIncludeEmailInRedirect(false); // Configurable: Usually false for privacy/cleaner URLs

        try {
            String ticketUrl = mgmt.tickets()
                    .requestPasswordChange(ticketRequest)
                    .addParameter("ttl_sec", 86400) // Ticket valid for 24 hours
                    .execute()
                    .getBody()
                    .getTicket();
            log.info("Successfully generated password change ticket URL for user {}", user.getId());
            return ticketUrl;
        } catch (Auth0Exception e) {
            log.error("Failed to generate password change ticket for user {}: {}", user.getId(), e.getMessage());
            throw e;
        }
    }

    private void attemptUserDeletionRollback(String userId) {
        try {
            log.warn("Attempting transaction rollback: Deleting user with ID {} due to creation process failure.", userId);
            ManagementAPI mgmt = auth0Config.getRefreshedManagementAPI();
            mgmt.users().delete(userId).execute();
            log.info("Rollback successful: Deleted user with ID {}", userId);
        } catch (Auth0Exception rollbackEx) {
            // Log the rollback failure, but don't throw, as the original error is more important
            log.error("Rollback failed: Could not delete user with ID {} during cleanup: {}", userId, rollbackEx.getMessage(), rollbackEx);
        }
    }

    private char[] generateRandomPasswordChars(int length) {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[length * 3 / 4 + 1]; // Ensure enough bytes for encoding
        random.nextBytes(bytes);
        String passwordString = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).substring(0, length);
        char[] passwordChars = passwordString.toCharArray();
        return passwordChars;
    }

    @Override
    public Mono<PaginatedUserResponse> listUsers(int page, int size) {
        return fetchUsersPageFromAuth0(page, size)
                .flatMap(usersPage -> buildPaginatedUserResponse(usersPage, page, size))
                .subscribeOn(Schedulers.boundedElastic());
    }

    private Mono<UsersPage> fetchUsersPageFromAuth0(int page, int size) {
        return Mono.fromCallable(() -> {
            ManagementAPI mgmt = auth0Config.getRefreshedManagementAPI();
            UserFilter filter = new UserFilter()
                    .withPage(page, size)
                    .withTotals(true);
            try {
                return mgmt.users().list(filter).execute().getBody();
            } catch (Auth0Exception e) {
                log.error("Error fetching users page from Auth0 (page={}, size={}): {}", page, size, e.getMessage(), e);
                throw new RuntimeException("Failed to list users from Auth0", e);
            }
        });
    }

    private Mono<PaginatedUserResponse> buildPaginatedUserResponse(UsersPage usersPage, int page, int size) {
        Flux<UserResponse> userResponseFlux = Flux.fromIterable(usersPage.getItems())
                .flatMap(this::mapUserToResponse);

        return userResponseFlux.collectList().map(userResponses -> {
            long totalElements = usersPage.getTotal();
            int totalPages = (size > 0) ? (int) Math.ceil((double) totalElements / size) : 0;

            return PaginatedUserResponse.builder()
                    .content(userResponses)
                    .currentPage(page)
                    .pageSize(size)
                    .totalElements(totalElements)
                    .totalPages(totalPages)
                    .build();
        });
    }

    private Mono<UserResponse> mapUserToResponse(User user) {
        return Mono.fromCallable(() -> {
                    ManagementAPI mgmt = auth0Config.getRefreshedManagementAPI();
                    List<Role> roles = mgmt.users().listRoles(user.getId(), null).execute().getBody().getItems();
                    List<String> roleNames = roles.stream().map(Role::getName).collect(Collectors.toList());

                    return UserResponse.builder()
                            .userId(user.getId())
                            .email(user.getEmail())
                            .name(user.getName())
                            .picture(user.getPicture())
                            .lastLogin(user.getLastLogin() != null ? user.getLastLogin().toString() : null)
                            .roles(roleNames)
                            .build();
                })
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(Auth0Exception.class, e -> {
                    log.error("Error fetching roles for user {}: {}", user.getId(), e.getMessage());
                    return Mono.just(UserResponse.builder()
                            .userId(user.getId())
                            .email(user.getEmail())
                            .name(user.getName())
                            .picture(user.getPicture())
                            .lastLogin(user.getLastLogin() != null ? user.getLastLogin().toString() : null)
                            .roles(Collections.emptyList())
                            .build());
                });
    }

    @Override
    public Mono<UserResponse> getUserById(String userId) {
        return Mono.fromCallable(() -> {
                    ManagementAPI mgmt = auth0Config.getRefreshedManagementAPI();
                    return mgmt.users().get(userId, null).execute().getBody();
                })
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(this::mapUserToResponse);
    }

    @Override
    public Mono<Void> deleteUser(String userId) {
        return Mono.fromRunnable(() -> {
            try {
                ManagementAPI mgmt = auth0Config.getRefreshedManagementAPI();
                mgmt.users().delete(userId).execute();
                log.info("Deleted Auth0 user with ID: {}", userId);
            } catch (Auth0Exception e) {
                log.error("Error deleting Auth0 user with ID {}: {}", userId, e.getMessage(), e);
                throw new RuntimeException("Failed to delete user in Auth0", e);
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    // ... (Update user stub needs updated UpdateUserRequest import if uncommented) ...
} 