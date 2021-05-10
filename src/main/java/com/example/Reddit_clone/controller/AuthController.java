package com.example.Reddit_clone.controller;
import com.example.Reddit_clone.dto.AuthenticationResponse;
import com.example.Reddit_clone.dto.LoginRequest;
import com.example.Reddit_clone.dto.RefreshTokenRequest;
import com.example.Reddit_clone.dto.RegisterRequest;
import com.example.Reddit_clone.service.AuthService;
import com.example.Reddit_clone.service.RefreshTokenService;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

import static org.springframework.http.HttpStatus.OK;

@RestController
@RequestMapping("/api/auth")
@AllArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final RefreshTokenService refreshTokenService;


    //invoked whenever a POST request is made to register the user’s in our application
    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody RegisterRequest registerRequest)  {
            authService.signup(registerRequest);
        return new ResponseEntity<>("User Registration Successful",
                OK);
    }
    //invoked whenever a POST request is made to authenticate the user in our application
    @PostMapping("/login")
    public AuthenticationResponse login(@RequestBody LoginRequest loginRequest) {
        return authService.login(loginRequest);
    }

    //invoked when a client access the link from the email to activate the account
    @GetMapping("accountVerification/{token}")
    public ResponseEntity<String> verifyAccount(@PathVariable String token){
        authService.verifyAccount(token);
        return new ResponseEntity<>("Account activated successfully", OK);
    }

    @PostMapping("/refresh/token")
    public AuthenticationResponse refreshTokens(@Valid @RequestBody RefreshTokenRequest refreshTokenRequest) {
        return authService.refreshToken(refreshTokenRequest);
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@Valid @RequestBody RefreshTokenRequest refreshTokenRequest) {
        refreshTokenService.deleteRefreshToken(refreshTokenRequest.getRefreshToken());

        return ResponseEntity.status(OK).body("Refresh Token Deleted Successfully!!");

    }
}