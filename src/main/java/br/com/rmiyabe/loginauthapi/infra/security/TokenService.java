package br.com.rmiyabe.loginauthapi.infra.security;

import br.com.rmiyabe.loginauthapi.domain.entities.User;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class TokenService {
    @Value("${api.security.token.secret}")
    private String secret;

    public String generateToken(User user) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);
            return JWT.create()
                   .withIssuer("login-auth-api")//quem vai emitir o token
                   .withSubject(user.getEmail())//quem vai receber o token salvando o email do usuario no token
                   .withExpiresAt(this.generateExpirationTime())//tempo que expira
                   .sign(algorithm);
        } catch (JWTCreationException e){
           throw new RuntimeException("Erro ao gerar token");
        }
    }

    public String validateToken(String token) {
       try {
           Algorithm algorithm = Algorithm.HMAC256(secret);
           return JWT.require(algorithm)
                   .withIssuer("login-auth-api")
                   .build()//constroi o token
                   .verify(token)
                   .getSubject();//retorna o subject do generate token
       }catch (JWTVerificationException e){
           return null;
       }
    }

    private Instant generateExpirationTime() {
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-3"));
    }
}
