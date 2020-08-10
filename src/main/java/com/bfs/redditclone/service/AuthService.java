package com.bfs.redditclone.service;

import com.bfs.redditclone.dto.LoginRequest;
import com.bfs.redditclone.dto.RegisterRequest;
import com.bfs.redditclone.exceptions.SpringRedditException;
import com.bfs.redditclone.model.NotificationEmail;
import com.bfs.redditclone.model.User;
import com.bfs.redditclone.model.VerificationToken;
import com.bfs.redditclone.repository.UserRepository;
import com.bfs.redditclone.repository.VerificationTokenRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
// this annotation will do constructor injection automatically
@AllArgsConstructor
public class AuthService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final VerificationTokenRepository verificationTokenRepository;
    private final MailService mailService;
    private final AuthenticationManager authenticationManager;

    @Transactional
    public void signup(RegisterRequest registerRequest) {
        User user = User.builder().username(registerRequest.getUsername()).email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .created(Instant.now()).enabled(false).build();
        userRepository.save(user);

        String token = generateVerificationToken(user);
        // here we have to connect to gmail and send the email
        // which will take a long time. We don't want the User to
        // wait for 10 seconds
        mailService.sendMail(new NotificationEmail("Please Activate your Account", user.getEmail(),
                "Dear User,\n\nThank you for signing up to Spring Reddit. \n" +
                        "Please click on the below url to activate your account : " +
                        "http://localhost:8080/api/auth/accountVerification/" + token +
                        "\n\n All the best,\nBeaconFire Team"));
    }

    private String generateVerificationToken(User user) {
        // universally unique immutable 128 bit token
        String token = UUID.randomUUID().toString();
        VerificationToken verificationToken = VerificationToken.builder().token(token).user(user).build();
        verificationTokenRepository.save(verificationToken);
        return token;
    }

    public void verifyAccount(String token) {
        Optional<VerificationToken> verificationToken = verificationTokenRepository.findByToken(token);
        verificationToken.orElseThrow(() -> new SpringRedditException("Invalid Token"));
        fetchUserAndEnable(verificationToken.get());
    }

    @Transactional
    public void fetchUserAndEnable(VerificationToken verificationToken) {
        long userId = verificationToken.getUser().getUserId();
        User user = userRepository.findByUserId(userId).orElseThrow(() -> new SpringRedditException("User not found with name - " + userId));
        user.setEnabled(true);
        userRepository.save(user);
    }

    public void login(LoginRequest loginRequest) {
        Authentication authenticate = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                loginRequest.getUsername(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authenticate);
    }
}
