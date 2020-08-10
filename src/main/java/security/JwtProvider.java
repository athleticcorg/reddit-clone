package security;

import com.bfs.redditclone.exceptions.SpringRedditException;
import io.jsonwebtoken.Jwts;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
//import java.time.Instant;
//import java.sql.Date;

@Service
public class JwtProvider {

    private KeyStore keyStore;

    public void init() {
        try {
            keyStore = KeyStore.getInstance("JKS");
            InputStream resourceAsStream = getClass().getResourceAsStream("/springreddit.jks");
            keyStore.load(resourceAsStream, "secrect".toCharArray());
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            throw new SpringRedditException("Exception occurred while loading keystore", e);
        }
    }

    public String generateToken(Authentication authentication) {
        User principal = (User) authentication.getPrincipal();
        return Jwts.builder().setSubject(principal.getUsername())
                .signWith(getPrivateKey())
                .compact();
                //.setIssuedAt(from(Instant.now()))
                //.setExpiration(Date.from(Instant.now().plusMillis(jwtExpirationInMillis))
    }

    private PrivateKey getPrivateKey() {
        try {
            return (PrivateKey) keyStore.getKey("springreddit", "secret".toCharArray());
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new SpringRedditException("Exception occured while retrieving public key from keystore", e);
        }
    }
}
