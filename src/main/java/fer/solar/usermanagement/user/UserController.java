package fer.solar.usermanagement.user;

import fer.solar.usermanagement.user.dto.CreateUserRequest;
import fer.solar.usermanagement.user.dto.CreateUserResponse;
import fer.solar.usermanagement.user.dto.PaginatedUserResponse;
import fer.solar.usermanagement.user.dto.UserResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping
    public Mono<CreateUserResponse> createUser(@RequestBody CreateUserRequest createUserRequest) {
        return userService.createUser(createUserRequest);
    }

    @GetMapping
    public Mono<PaginatedUserResponse> listUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size
    ) {
        if (size < 1) {
            size = 20;
        }
        if (page < 0) {
            page = 0;
        }
        return userService.listUsers(page, size);
    }

    @GetMapping("/{userId}")
    public Mono<ResponseEntity<UserResponse>> getUserById(@PathVariable String userId) {
        return userService.getUserById(userId)
                .map(ResponseEntity::ok)
                .defaultIfEmpty(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{userId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> deleteUser(@PathVariable String userId) {
        return userService.deleteUser(userId);
    }

    // Note: Update endpoint implementation depends on the specific requirements
    // Example placeholder:
    /*
    @PutMapping("/{userId}")
    public Mono<ResponseEntity<UserResponse>> updateUser(@PathVariable String userId, @RequestBody UpdateUserRequest updateUserRequest) {
        // Assumes UpdateUserRequest exists in user.dto package
        // return userService.updateUser(userId, updateUserRequest)
        //         .map(ResponseEntity::ok)
        //         .defaultIfEmpty(ResponseEntity.notFound().build());
    }
    */
} 