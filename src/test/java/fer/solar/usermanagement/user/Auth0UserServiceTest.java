package fer.solar.usermanagement.user;

import com.auth0.client.mgmt.ManagementAPI;
import com.auth0.client.mgmt.UsersEntity;
import com.auth0.client.mgmt.TicketsEntity;
import com.auth0.client.mgmt.filter.UserFilter;
import com.auth0.exception.APIException;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.mgmt.roles.Role;
import com.auth0.json.mgmt.roles.RolesPage;
import com.auth0.json.mgmt.tickets.PasswordChangeTicket;
import com.auth0.json.mgmt.users.User;
import com.auth0.json.mgmt.users.UsersPage;
import com.auth0.net.Request;
import com.auth0.net.Response;
import fer.solar.usermanagement.config.Auth0Config;
import fer.solar.usermanagement.user.dto.CreateUserRequest;
import fer.solar.usermanagement.user.dto.CreateUserResponse;
import fer.solar.usermanagement.user.dto.PaginatedUserResponse;
import fer.solar.usermanagement.user.dto.UserResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.doReturn;

@ExtendWith(MockitoExtension.class)
class Auth0UserServiceTest {

    @Mock
    private Auth0Config auth0Config;
    @Mock
    private ManagementAPI managementAPI;
    @Mock
    private UsersEntity users;
    @Mock
    private TicketsEntity tickets;

    @Mock
    private Request<User> createUserRequestMock;
    @Mock
    private Request<Void> addRolesRequestMock;
    @Mock
    private Request<PasswordChangeTicket> createTicketRequestMock;
    @Mock
    private Request<Void> deleteUserRequestMock;

    @Mock
    private Request<UsersPage> listUsersRequestMock;

    @Mock
    private Request<User> getUserRequestMock;

    @InjectMocks
    private Auth0UserService auth0UserService;

    @Captor
    private ArgumentCaptor<User> userCaptor;
    @Captor
    private ArgumentCaptor<List<String>> rolesCaptor;
    @Captor
    private ArgumentCaptor<PasswordChangeTicket> ticketRequestCaptor;
    @Captor
    private ArgumentCaptor<String> userIdCaptor;

    @Captor
    private ArgumentCaptor<UserFilter> userFilterCaptor;

    private CreateUserRequest defaultCreateRequest;
    private User createdUserMock;
    private final String expectedTicketUrl = "https://your-tenant.auth0.com/tickets/tic_abcdef123456";

    private User user1;
    private User user2;

    @BeforeEach
    void setUp() {
        when(auth0Config.getRefreshedManagementAPI()).thenReturn(managementAPI);
        when(managementAPI.users()).thenReturn(users);
    }

    private void setupCreateUserTestData() {
        defaultCreateRequest = new CreateUserRequest();
        defaultCreateRequest.setEmail("test@example.com");
        defaultCreateRequest.setConnection("Username-Password-Authentication");
        defaultCreateRequest.setRoleIds(Arrays.asList("role_id_1", "role_id_2"));
        defaultCreateRequest.setResultUrl("http://localhost:3000/reset-password");

        createdUserMock = new User(defaultCreateRequest.getConnection());
        createdUserMock.setEmail(defaultCreateRequest.getEmail());
        createdUserMock.setId("auth0|usr_test_123456");
    }

    private void setupListUsersTestData() {
        user1 = new User("conn");
        user1.setId("user|1");
        user1.setEmail("user1@test.com");
        user1.setName("User One");

        user2 = new User("conn");
        user2.setId("user|2");
        user2.setEmail("user2@test.com");
        user2.setName("User Two");
    }

    @Test
    void createUser_should_returnTicketUrl_when_allStepsSucceed() throws Auth0Exception {
        setupCreateUserTestData();
        mockUserCreationSuccess();
        mockRoleAssignmentSuccess();
        mockTicketGenerationSuccess();

        Mono<CreateUserResponse> resultMono = auth0UserService.createUser(defaultCreateRequest);

        StepVerifier.create(resultMono)
                .expectNextMatches(response -> response.getTicketUrl().equals(expectedTicketUrl))
                .verifyComplete();

        User capturedUser = userCaptor.getValue();
        assertThat(capturedUser.getEmail()).isEqualTo(defaultCreateRequest.getEmail());
        assertThat(capturedUser.isEmailVerified()).isFalse();

        assertThat(userIdCaptor.getAllValues()).contains(createdUserMock.getId());
        assertThat(rolesCaptor.getValue()).isEqualTo(defaultCreateRequest.getRoleIds());

        PasswordChangeTicket capturedTicketRequest = ticketRequestCaptor.getValue();
        assertThat(capturedTicketRequest).isNotNull();
        verify(createTicketRequestMock).addParameter("ttl_sec", 86400);

        verify(users, never()).delete(anyString());
    }

    @Test
    void createUser_should_returnTicketUrl_when_noRolesProvided() throws Auth0Exception {
        setupCreateUserTestData();
        CreateUserRequest requestWithNoRoles = new CreateUserRequest();
        requestWithNoRoles.setEmail(defaultCreateRequest.getEmail());
        requestWithNoRoles.setConnection(defaultCreateRequest.getConnection());
        requestWithNoRoles.setRoleIds(Collections.emptyList());
        requestWithNoRoles.setResultUrl(defaultCreateRequest.getResultUrl());

        mockUserCreationSuccess();
        mockTicketGenerationSuccess();

        Mono<CreateUserResponse> resultMono = auth0UserService.createUser(requestWithNoRoles);

        StepVerifier.create(resultMono)
                .expectNextMatches(response -> response.getTicketUrl().equals(expectedTicketUrl))
                .verifyComplete();

        verify(users).create(any(User.class));
        verify(users, never()).addRoles(anyString(), anyList());
        verify(tickets).requestPasswordChange(any(PasswordChangeTicket.class));
        verify(users, never()).delete(anyString());
    }

    @Test
    void createUser_should_throwExceptionAndRollback_when_roleAssignmentFails() throws Auth0Exception {
        setupCreateUserTestData();
        APIException roleException = createApiException("Role assignment failed", 500);
        mockUserCreationSuccess();
        mockRoleAssignmentFailure(roleException);
        mockUserDeletionSuccess();

        Mono<CreateUserResponse> resultMono = auth0UserService.createUser(defaultCreateRequest);

        StepVerifier.create(resultMono)
                .expectErrorSatisfies(throwable -> {
                    assertThat(throwable).isInstanceOf(RuntimeException.class)
                            .hasMessageContaining("Failed to complete user creation process")
                            .hasCause(roleException);
                })
                .verify();

        verify(users).delete(createdUserMock.getId());
    }

    @Test
    void createUser_should_throwExceptionAndRollback_when_ticketGenerationFails() throws Auth0Exception {
        setupCreateUserTestData();
        APIException ticketException = createApiException("Ticket generation failed", 500);
        mockUserCreationSuccess();
        mockRoleAssignmentSuccess();
        mockTicketGenerationFailure(ticketException);
        mockUserDeletionSuccess();

        Mono<CreateUserResponse> resultMono = auth0UserService.createUser(defaultCreateRequest);

        StepVerifier.create(resultMono)
                .expectErrorSatisfies(throwable -> {
                    assertThat(throwable).isInstanceOf(RuntimeException.class)
                            .hasMessageContaining("Failed to complete user creation process")
                            .hasCause(ticketException);
                })
                .verify();

        verify(users).delete(createdUserMock.getId());
    }

    @Test
    void createUser_should_throwException_when_userCreationFails() throws Auth0Exception {
        setupCreateUserTestData();
        APIException createException = createApiException("User creation failed", 400);
        mockUserCreationFailure(createException);

        Mono<CreateUserResponse> resultMono = auth0UserService.createUser(defaultCreateRequest);

        StepVerifier.create(resultMono)
                .expectErrorSatisfies(throwable -> {
                    assertThat(throwable).isInstanceOf(RuntimeException.class)
                            .hasMessageContaining("Failed to complete user creation process")
                            .hasCause(createException);
                })
                .verify();

        verify(users, never()).addRoles(anyString(), anyList());
        verify(tickets, never()).requestPasswordChange(any(PasswordChangeTicket.class));
        verify(users, never()).delete(anyString());
    }

    @Test
    void createUser_should_throwOriginalException_when_rollbackFails() throws Auth0Exception {
        setupCreateUserTestData();
        APIException roleException = createApiException("Role assignment failed", 500);
        APIException deleteException = createApiException("Delete during rollback failed", 500);
        mockUserCreationSuccess();
        mockRoleAssignmentFailure(roleException);
        mockUserDeletionFailure(deleteException);

        Mono<CreateUserResponse> resultMono = auth0UserService.createUser(defaultCreateRequest);

        StepVerifier.create(resultMono)
                .expectErrorSatisfies(throwable -> {
                    assertThat(throwable).isInstanceOf(RuntimeException.class)
                            .hasMessageContaining("Failed to complete user creation process")
                            .hasCause(roleException);
                })
                .verify();

        verify(users).delete(createdUserMock.getId());
    }

    @Test
    void listUsers_should_returnPaginatedResponseWithUsersAndRoles_when_allApiCallsSucceed() throws Auth0Exception {
        setupListUsersTestData();
        int page = 0;
        int size = 10;
        long totalUsers = 2;

        UsersPage usersPageResponse = mockUsersPage(Arrays.asList(user1, user2), totalUsers);
        mockListUsersSuccess(usersPageResponse);

        mockListRolesSuccess(user1.getId(), Arrays.asList("Role1"));
        mockListRolesSuccess(user2.getId(), Arrays.asList("Role1", "Role2"));

        Mono<PaginatedUserResponse> resultMono = auth0UserService.listUsers(page, size);

        StepVerifier.create(resultMono)
            .assertNext(response -> {
                assertThat(response.getCurrentPage()).isEqualTo(page);
                assertThat(response.getPageSize()).isEqualTo(size);
                assertThat(response.getTotalElements()).isEqualTo(totalUsers);
                assertThat(response.getTotalPages()).isEqualTo(1);
                assertThat(response.getContent()).hasSize(2);

                assertThat(response.getContent()).anySatisfy(resUser -> {
                    assertThat(resUser.getUserId()).isEqualTo(user1.getId());
                    assertThat(resUser.getRoles()).containsExactly("Role1");
                });
                assertThat(response.getContent()).anySatisfy(resUser -> {
                    assertThat(resUser.getUserId()).isEqualTo(user2.getId());
                    assertThat(resUser.getRoles()).containsExactlyInAnyOrder("Role1", "Role2");
                });
            })
            .verifyComplete();

        verify(users).list(userFilterCaptor.capture());
        assertThat(userFilterCaptor.getValue().getAsMap()).containsEntry("page", page);
        assertThat(userFilterCaptor.getValue().getAsMap()).containsEntry("per_page", size);
        assertThat(userFilterCaptor.getValue().getAsMap()).containsEntry("include_totals", true);

        verify(users).listRoles(eq(user1.getId()), isNull());
        verify(users).listRoles(eq(user2.getId()), isNull());
    }

    @Test
    void listUsers_should_returnEmptyPaginatedResponse_when_noUsersFound() throws Auth0Exception {
        setupListUsersTestData();
        int page = 0;
        int size = 10;
        UsersPage emptyUsersPage = mockUsersPage(Collections.emptyList(), 0L);
        mockListUsersSuccess(emptyUsersPage);

        Mono<PaginatedUserResponse> resultMono = auth0UserService.listUsers(page, size);

        StepVerifier.create(resultMono)
            .assertNext(response -> {
                assertThat(response.getCurrentPage()).isEqualTo(page);
                assertThat(response.getPageSize()).isEqualTo(size);
                assertThat(response.getTotalElements()).isEqualTo(0);
                assertThat(response.getTotalPages()).isEqualTo(0);
                assertThat(response.getContent()).isEmpty();
            })
            .verifyComplete();

        verify(users).list(any(UserFilter.class));
        verify(users, never()).listRoles(anyString(), any());
    }

    @Test
    void listUsers_should_throwException_when_fetchingUsersPageFails() throws Auth0Exception {
        setupListUsersTestData();
        int page = 0;
        int size = 10;
        APIException listUsersException = createApiException("Failed to list users", 500);
        mockListUsersFailure(listUsersException);

        Mono<PaginatedUserResponse> resultMono = auth0UserService.listUsers(page, size);

        StepVerifier.create(resultMono)
            .expectErrorSatisfies(throwable -> {
                assertThat(throwable).isInstanceOf(RuntimeException.class)
                        .hasMessageContaining("Failed to list users from Auth0")
                        .hasCause(listUsersException);
            })
            .verify();

        verify(users).list(any(UserFilter.class));
        verify(users, never()).listRoles(anyString(), any());
    }

    @Test
    void listUsers_should_returnUsersWithEmptyRoles_when_fetchingRolesFailsForOneUser() throws Auth0Exception {
        setupListUsersTestData();
        int page = 0;
        int size = 10;
        long totalUsers = 2;

        UsersPage usersPageResponse = mockUsersPage(Arrays.asList(user1, user2), totalUsers);
        mockListUsersSuccess(usersPageResponse);

        APIException listRolesException = createApiException("Failed to list roles for user 2", 500);
        mockListRolesSuccess(user1.getId(), Arrays.asList("Role1"));
        mockListRolesFailure(user2.getId(), listRolesException);

        Mono<PaginatedUserResponse> resultMono = auth0UserService.listUsers(page, size);

        StepVerifier.create(resultMono)
            .assertNext(response -> {
                assertThat(response.getTotalElements()).isEqualTo(totalUsers);
                assertThat(response.getContent()).hasSize(2);

                UserResponse resUser1 = response.getContent().get(0);
                assertThat(resUser1.getUserId()).isEqualTo(user1.getId());
                assertThat(resUser1.getRoles()).containsExactly("Role1");

                UserResponse resUser2 = response.getContent().get(1);
                assertThat(resUser2.getUserId()).isEqualTo(user2.getId());
                assertThat(resUser2.getRoles()).isEmpty();
            })
            .verifyComplete();

        verify(users).list(any(UserFilter.class));
        verify(users).listRoles(eq(user1.getId()), isNull());
        verify(users).listRoles(eq(user2.getId()), isNull());
    }

    @Test
    void listUsers_should_calculatePaginationCorrectly_when_sizeIsZeroOrLess() throws Auth0Exception {
        setupListUsersTestData();
        int page = 0;
        int size = 0;
        long totalUsers = 5;

        UsersPage usersPageResponse = mockUsersPage(Collections.emptyList(), totalUsers);
        mockListUsersSuccess(usersPageResponse);

        Mono<PaginatedUserResponse> resultMono = auth0UserService.listUsers(page, size);

        StepVerifier.create(resultMono)
            .assertNext(response -> {
                assertThat(response.getCurrentPage()).isEqualTo(page);
                assertThat(response.getPageSize()).isEqualTo(size);
                assertThat(response.getTotalElements()).isEqualTo(totalUsers);
                assertThat(response.getTotalPages()).isEqualTo(0);
                assertThat(response.getContent()).isEmpty();
            })
            .verifyComplete();

        verify(users).list(userFilterCaptor.capture());
        assertThat(userFilterCaptor.getValue().getAsMap()).containsEntry("per_page", size);
        verify(users, never()).listRoles(anyString(), any());
    }

    private void mockUserCreationSuccess() throws Auth0Exception {
        Response<User> mockResp = createMockResponse(createdUserMock);
        when(users.create(userCaptor.capture())).thenReturn(createUserRequestMock);
        when(createUserRequestMock.execute()).thenReturn(mockResp);
    }

    private void mockUserCreationFailure(Auth0Exception exception) throws Auth0Exception {
        when(users.create(any(User.class))).thenReturn(createUserRequestMock);
        when(createUserRequestMock.execute()).thenThrow(exception);
    }

    private void mockRoleAssignmentSuccess() throws Auth0Exception {
        Response<Void> mockResp = createMockResponse(null);
        when(users.addRoles(userIdCaptor.capture(), rolesCaptor.capture())).thenReturn(addRolesRequestMock);
        when(addRolesRequestMock.execute()).thenReturn(mockResp);
    }

    private void mockRoleAssignmentFailure(Auth0Exception exception) throws Auth0Exception {
        when(users.addRoles(anyString(), anyList())).thenReturn(addRolesRequestMock);
        when(addRolesRequestMock.execute()).thenThrow(exception);
    }

    private void mockTicketGenerationSuccess() throws Auth0Exception {
        when(managementAPI.tickets()).thenReturn(tickets);
        PasswordChangeTicket mockResponseBody = Mockito.mock(PasswordChangeTicket.class);
        when(mockResponseBody.getTicket()).thenReturn(expectedTicketUrl);
        Response<PasswordChangeTicket> mockResp = createMockResponse(mockResponseBody);
        when(tickets.requestPasswordChange(ticketRequestCaptor.capture())).thenReturn(createTicketRequestMock);
        when(createTicketRequestMock.addParameter(anyString(), any())).thenReturn(createTicketRequestMock);
        when(createTicketRequestMock.execute()).thenReturn(mockResp);
    }

    private void mockTicketGenerationFailure(Auth0Exception exception) throws Auth0Exception {
        when(managementAPI.tickets()).thenReturn(tickets);
        when(tickets.requestPasswordChange(any(PasswordChangeTicket.class))).thenReturn(createTicketRequestMock);
        when(createTicketRequestMock.addParameter(anyString(), any())).thenReturn(createTicketRequestMock);
        when(createTicketRequestMock.execute()).thenThrow(exception);
    }

    private void mockUserDeletionSuccess() throws Auth0Exception {
        Response<Void> mockResp = createMockResponse(null);
        when(users.delete(userIdCaptor.capture())).thenReturn(deleteUserRequestMock);
        when(deleteUserRequestMock.execute()).thenReturn(mockResp);
    }

    private void mockUserDeletionFailure(Auth0Exception exception) throws Auth0Exception {
        when(users.delete(anyString())).thenReturn(deleteUserRequestMock);
        when(deleteUserRequestMock.execute()).thenThrow(exception);
    }

    private void mockListUsersSuccess(UsersPage responsePage) throws Auth0Exception {
        Response<UsersPage> mockResp = createMockResponse(responsePage);
        when(users.list(any(UserFilter.class))).thenReturn(listUsersRequestMock);
        when(listUsersRequestMock.execute()).thenReturn(mockResp);
    }

    private void mockListUsersFailure(Auth0Exception exception) throws Auth0Exception {
        when(users.list(any(UserFilter.class))).thenReturn(listUsersRequestMock);
        when(listUsersRequestMock.execute()).thenThrow(exception);
    }

    private void mockListRolesSuccess(String userId, List<String> roleNames) throws Auth0Exception {
        RolesPage responsePage = mockRolesPage(roleNames);
        Response<RolesPage> mockResp = createMockResponse(responsePage);

        @SuppressWarnings("unchecked")
        Request<RolesPage> localRequestMock = (Request<RolesPage>) mock(Request.class);
        when(users.listRoles(eq(userId), isNull())).thenReturn(localRequestMock);
        when(localRequestMock.execute()).thenReturn(mockResp);
    }

    private void mockListRolesFailure(String userId, Auth0Exception exception) throws Auth0Exception {
        @SuppressWarnings("unchecked")
        Request<RolesPage> localRequestMock = (Request<RolesPage>) mock(Request.class);
        when(users.listRoles(eq(userId), isNull())).thenReturn(localRequestMock);
        when(localRequestMock.execute()).thenThrow(exception);
    }

    private <T> Response<T> createMockResponse(T body) {
        @SuppressWarnings("unchecked")
        Response<T> mockResponse = (Response<T>) mock(Response.class);
        lenient().when(mockResponse.getBody()).thenReturn(body);
        return mockResponse;
    }

    private APIException createApiException(String message, int statusCode) {
        Map<String, Object> values = new HashMap<>();
        values.put("error", "test_error_code");
        values.put("error_description", message);
        return new APIException(values, statusCode);
    }

    private UsersPage mockUsersPage(List<User> users, Long total) {
        UsersPage page = Mockito.mock(UsersPage.class);
        when(page.getItems()).thenReturn(users != null ? users : Collections.emptyList());
        doReturn(total != null ? total.intValue() : 0).when(page).getTotal();
        return page;
    }

    private RolesPage mockRolesPage(List<String> roleNames) {
        List<Role> mockRoles = new ArrayList<>();
        if (roleNames != null) {
            for (String name : roleNames) {
                Role mockRole = Mockito.mock(Role.class);
                when(mockRole.getName()).thenReturn(name);
                mockRoles.add(mockRole);
            }
        }
        RolesPage page = Mockito.mock(RolesPage.class);
        when(page.getItems()).thenReturn(mockRoles);
        return page;
    }

    private void mockGetUserSuccess(String userId, User responseUser) throws Auth0Exception {
        Response<User> mockResp = createMockResponse(responseUser);
        when(users.get(eq(userId), isNull())).thenReturn(getUserRequestMock);
        when(getUserRequestMock.execute()).thenReturn(mockResp);
    }

    private void mockGetUserFailure(String userId, Auth0Exception exception) throws Auth0Exception {
        when(users.get(eq(userId), isNull())).thenReturn(getUserRequestMock);
        when(getUserRequestMock.execute()).thenThrow(exception);
    }

    @Test
    void getUserById_should_returnUserResponseWithRoles_when_userAndRolesFound() throws Auth0Exception {
        setupListUsersTestData();
        String targetUserId = user1.getId();
        List<String> expectedRoles = Arrays.asList("Role1", "Role2");

        mockGetUserSuccess(targetUserId, user1);
        mockListRolesSuccess(targetUserId, expectedRoles);

        Mono<UserResponse> resultMono = auth0UserService.getUserById(targetUserId);

        StepVerifier.create(resultMono)
            .assertNext(userResponse -> {
                assertThat(userResponse.getUserId()).isEqualTo(targetUserId);
                assertThat(userResponse.getEmail()).isEqualTo(user1.getEmail());
                assertThat(userResponse.getName()).isEqualTo(user1.getName());
                assertThat(userResponse.getRoles()).containsExactlyInAnyOrderElementsOf(expectedRoles);
            })
            .verifyComplete();

        verify(users).get(eq(targetUserId), isNull());
        verify(users).listRoles(eq(targetUserId), isNull());
    }

    @Test
    void getUserById_should_returnUserResponseWithEmptyRoles_when_userFoundButListRolesFails() throws Auth0Exception {
        setupListUsersTestData();
        String targetUserId = user1.getId();
        APIException rolesException = createApiException("Failed to get roles", 500);

        mockGetUserSuccess(targetUserId, user1);
        mockListRolesFailure(targetUserId, rolesException);

        Mono<UserResponse> resultMono = auth0UserService.getUserById(targetUserId);

        StepVerifier.create(resultMono)
            .assertNext(userResponse -> {
                assertThat(userResponse.getUserId()).isEqualTo(targetUserId);
                assertThat(userResponse.getEmail()).isEqualTo(user1.getEmail());
                assertThat(userResponse.getName()).isEqualTo(user1.getName());
                assertThat(userResponse.getRoles()).isEmpty();
            })
            .verifyComplete();

        verify(users).get(eq(targetUserId), isNull());
        verify(users).listRoles(eq(targetUserId), isNull());
    }

    @Test
    void getUserById_should_throwException_when_userNotFound() throws Auth0Exception {
        setupListUsersTestData();
        String targetUserId = "user|nonexistent";
        APIException getException = createApiException("User not found", 404);

        mockGetUserFailure(targetUserId, getException);

        Mono<UserResponse> resultMono = auth0UserService.getUserById(targetUserId);

        StepVerifier.create(resultMono)
            .expectErrorSatisfies(throwable -> {
                assertThat(throwable).isInstanceOf(APIException.class)
                        .isSameAs(getException);
            })
            .verify();

        verify(users).get(eq(targetUserId), isNull());
        verify(users, never()).listRoles(anyString(), any());
    }

    @Test
    void deleteUser_should_completeSuccessfully_when_deleteApiCallSucceeds() throws Auth0Exception {
        String targetUserId = "user|to_delete";
        mockUserDeletionSuccess();

        Mono<Void> resultMono = auth0UserService.deleteUser(targetUserId);

        StepVerifier.create(resultMono)
            .verifyComplete();

        verify(users).delete(eq(targetUserId));
    }

    @Test
    void deleteUser_should_throwException_when_deleteApiCallFails() throws Auth0Exception {
        String targetUserId = "user|to_delete";
        APIException deleteException = createApiException("Failed to delete", 500);
        mockUserDeletionFailure(deleteException);

        Mono<Void> resultMono = auth0UserService.deleteUser(targetUserId);

        StepVerifier.create(resultMono)
             .expectErrorSatisfies(throwable -> {
                assertThat(throwable).isInstanceOf(RuntimeException.class)
                        .hasMessageContaining("Failed to delete user in Auth0")
                        .hasCause(deleteException);
            })
            .verify();

        verify(users).delete(eq(targetUserId));
    }
} 