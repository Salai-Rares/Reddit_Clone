package com.example.Reddit_clone.service;
import com.example.Reddit_clone.dto.AuthenticationResponse;
import com.example.Reddit_clone.dto.LoginRequest;
import com.example.Reddit_clone.dto.RegisterRequest;

import com.example.Reddit_clone.exceptions.SpringRedditException;
import com.example.Reddit_clone.model.NotificationEmail;
import com.example.Reddit_clone.model.User;
import com.example.Reddit_clone.model.VerificationToken;
import com.example.Reddit_clone.repository.UserRepository;
import com.example.Reddit_clone.repository.VerificationTokenRepository;
import com.example.Reddit_clone.security.JwtProvider;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

import static java.time.Instant.now;

@Service
@AllArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtProvider jwtProvider;
    private final VerificationTokenRepository verificationTokenRepository;
    private final MailService mailService;

    //we are mapping the RegisterRequest object to the User object
    // and when setting the password, we are calling the encodePassword() method
    @Transactional
    public void signup(RegisterRequest registerRequest)  {
        User user = new User();
        user.setUsername(registerRequest.getUsername());
        user.setEmail(registerRequest.getEmail());
        user.setPassword(encodePassword(registerRequest.getPassword()));
        user.setCreated(now());
        user.setEnabled(false);

        userRepository.save(user);
        String token= generateVerificationToken(user);
        mailService.sendMail(new NotificationEmail("Please activate your account",user.getEmail(),
                "please click on the below url to activate your account: " + "http://localhost:8080/api/auth/accountVerification/"+token));
    }

    //added the generateVerificationToken() method and calling that method right after we saved the user into UserRepository.
    private String generateVerificationToken(User user){
        String token = UUID.randomUUID().toString();
        VerificationToken verificationToken = new VerificationToken();
        verificationToken.setToken(token);
        verificationToken.setUser(user);
        verificationTokenRepository.save(verificationToken);
        return token;
    }

    private String encodePassword(String password) {
        return passwordEncoder.encode(password);
    }
    /*
    The login request is received by AuthController and is passed on to the AuthService class.
    This class creates an object of type UserNamePasswordAuthenticationToken which
    encapsulates the username and password provided by the user as part of the login request.
    Then this is passed on to AuthenticationManager which takes care of the authentication part when using Spring Security.
    It implements lot of functionality in the background and provides us nice API we can use.
    The AuthenticationManager further interacts with an interface called UserDetailsService,
    this interface as the name suggests deals with user data.
    There are several implementations that can be used depending on the kind of authentication we want.
    There is support for in-memory authentication, database-authentication, LDAP based authentication.
    As we store our user information inside the Database, we used Database authentication,
    so the implementation access the database and retrieves the user details and passes UserDetails back to AuthenticationManager.
    The AuthenticationManger now checks the credentials,
    and if they match it creates an object of type Authentication and passes it back to the AuthService class.
    Then we create the JWT and respond back to the user.
     */
    public AuthenticationResponse login(LoginRequest loginRequest) {
        Authentication authenticate = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),
                loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authenticate);
        String authenticationToken = jwtProvider.generateToken(authenticate);
        return new AuthenticationResponse(authenticationToken, loginRequest.getUsername());
    }

    public void  verifyAccount(String token){
      Optional<VerificationToken> verificationToken = verificationTokenRepository.findByToken(token);
      verificationToken.orElseThrow(() -> new SpringRedditException("Invalid Token"));
      fetchUserAndEnable(verificationToken.get());
    }

    @Transactional
    public void fetchUserAndEnable(VerificationToken verificationToken){
        String username = verificationToken.getUser().getUsername(); // get the username associated with the verificationToken
        User user = userRepository.findByUsername(username).orElseThrow(() -> new SpringRedditException("User not found with name - " + username));
        user.setEnabled(true); // give the user permission to log in
        userRepository.save(user); // save the user to database

    }

    @Transactional(readOnly = true)
    public User getCurrentUser() {
        org.springframework.security.core.userdetails.User principal = (org.springframework.security.core.userdetails.User) SecurityContextHolder.
                getContext().getAuthentication().getPrincipal();
        return userRepository.findByUsername(principal.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("User name not found - " + principal.getUsername()));
    }

    public boolean isLoggedIn() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return !(authentication instanceof AnonymousAuthenticationToken) && authentication.isAuthenticated();
    }
}