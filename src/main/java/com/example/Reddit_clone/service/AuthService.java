package com.example.Reddit_clone.service;
import com.example.Reddit_clone.dto.RegisterRequest;

import com.example.Reddit_clone.exceptions.SpringRedditException;
import com.example.Reddit_clone.model.NotificationEmail;
import com.example.Reddit_clone.model.User;
import com.example.Reddit_clone.model.VerificationToken;
import com.example.Reddit_clone.repository.UserRepository;
import com.example.Reddit_clone.repository.VerificationTokenRepository;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

}