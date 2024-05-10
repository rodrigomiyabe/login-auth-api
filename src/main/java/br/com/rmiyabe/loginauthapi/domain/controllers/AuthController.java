package br.com.rmiyabe.loginauthapi.domain.controllers;

import br.com.rmiyabe.loginauthapi.domain.dtos.LoginRequestDTO;
import br.com.rmiyabe.loginauthapi.domain.dtos.RegisterDTO;
import br.com.rmiyabe.loginauthapi.domain.dtos.ResponseDTO;
import br.com.rmiyabe.loginauthapi.domain.entities.User;
import br.com.rmiyabe.loginauthapi.domain.repositories.UserRepository;
import br.com.rmiyabe.loginauthapi.infra.security.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    @PostMapping("/login")
    public ResponseEntity<ResponseDTO> login(@RequestBody LoginRequestDTO dto) {
        User user = this.userRepository.findByEmail(dto.email()).orElseThrow(() -> new RuntimeException("User not found!"));
        if (passwordEncoder.matches(dto.password(), user.getPassword())) {
            String token = this.tokenService.generateToken(user);
            return ResponseEntity.ok(new ResponseDTO(user.getUsername(), token));
        }
        return ResponseEntity.badRequest().build();
    }

    @PostMapping("/register")
    public ResponseEntity<ResponseDTO> register(@RequestBody RegisterDTO dto) {
        Optional<User> user = this.userRepository.findByEmail(dto.email());
        if (user.isEmpty()) {
            User newUser = new User();
            newUser.setEmail(dto.email());
            newUser.setPassword(passwordEncoder.encode(dto.password()));
            newUser.setUsername(dto.username());
            this.userRepository.save(newUser);
            String token = this.tokenService.generateToken(newUser);
            return ResponseEntity.ok(new ResponseDTO(newUser.getUsername(), token));
        }
        return ResponseEntity.badRequest().build();
    }

}
