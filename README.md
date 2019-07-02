# OpenSNS-BeterMetElkaar-SSOLaunchSamenBeter-Java

SNS Launch protocol code example in Java.

This repository provides Java code examples on how to implement the [SNS Launch protocol](https://github.com/GidsOpenStandaarden/OpenSNS-BeterMetElkaar-SSOLaunchSamenBeter-Protocol).

# Example 1. Generate a SNS Launch token with an RSA key

This example makes use of the auth0 JWT library. The key algorithm used is RSA.

```java
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.apache.commons.codec.binary.Base64;
 
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;
import java.util.UUID;
 
public class JwtConsumerExample {
    public static void main(String[] args) throws Exception {
        String resourceId = "dagstructuur";
        String subject = "urn:sns:user:issuer.nl:123456";
        String issuer = "issuer.nl";
        String audience = "audience.nl";
        String email = "klaas@devries.nl";
        String firstName = "Klaas";
        String middleName = "de";
        String lastName = "Vries";
        String privateK = "MIIEpwIBADANBgkqhkiG9w0BAQEFAASCBJEwggSNAgEAAoH+AL7TOqN8jbMq++PBTATgmItjJSprOnFYP6GbIsIReDN9scha/BEPngzw8moK370irc8Ei+lmgl7NDmvO0RY3o4juqherjKBnhhNcZT4St+ouW/Iy/899u4dTuhFL7hbSKraY/BBBdIowMnPipI5FrvmnrEwwd3fzEmAdDq0HA8UxvCGkawakIWnFGqUxHvfkPyBFuEVtJ7HEyFvKqlBOujS7rE8WgB5yV2IInwo2Wnb801xGAxkpUhTevCGnnYlycj3RvLxRmgPQi2VGhd1oGaZA5FZGubZILWtG74oWJ3OPF7ZxGIVVeq2Gp7VO2bb1q1R5V+0mESBvtSnEok8CAwEAAQKB/VO7cg6Mt8y3fsHIbqfxOV5oScWcOY/Erl8mKJFJgxns/JayvcpqtOpuy6AWV2ixj9y33QC0V15r0fkiTgLWtS5/sykhwFoeMunJ8C7VndfnMbdMA42zWRcfeRTf4YAoBlALPwePASklzu2ktJotH4MyvNrNpY5/nT+JYIgx/LxhIwk/HxJ6uVYiFpAINfAGfBphcgxzKWnV23WvRYtrIJc/XXLvSxK08tvoZfm4c4quf1i3LpTc+1mZmT+jefZoXQcWUnEbCk5Q/8gvDigHMbdOlTqT4/iNj/03PmueWsljiyhbXDYOVGJCaGQpeNaFnhilXPrYEBkAvXIOg6ECfw7l7td0wyPP0vCYFcbQEr3qng9vg2ISVas8gIOU/OeKNSJ9+wbKWcd0DAztxGShuqDZjBXj+RSEL1XrABjDpk9RqpgkBx3NNXEbCBnYg3+LU8HCtUBWi5amaJi8JH2839cVXjdZbPXBPmp5S93SKjmuoiBas8oKITh0yEwwdb8CfwzPAeg765BhD4AmwSzoQRy6Sfxf6R0Z8Uo9a2mxBiGSKPvX7zQMG384208FvTlaW3UoOAhSN6HsfBwWT9pzRIaWAkFP8CWxRiRqzg20FYzTweQZOnqje6YRYSocX64l22zhqV3Y3DdqevIiGpxDFqFM8QXeaAcchCvg6LpTl3ECfwqlC1RynwM1eLhjUhvti5aazjilKrCl/QQOhJx/lXwyaeitLvEZH7C9H+cU8+AbFmfbSJZTfyLDl7bB5B3NnUTLSyLNizAl8WtRLyaYZsx41m15G1xO+gm3+MA4nbIhg6YAJINTp+CoJFqbNDPX+EeimUCYziErv7TA7GRTs60Cfws28F+KnzzBjtXQmNCd5eymOwNKYovFXBt5XWOjyE96boHa1ahHdYfVm0c8KipeL7eLaEv42JbgvOXGr1IAHJ6OFxliSUxnQ5e9H/6ljzzHZ3s0j5wzKZ8EloNNZoTOxqk1h5oQtveaNl1seMoaf2TpPhq6WXDoidz1Ri9l4zECfmzg4k6Jo2YpZVAm1xQU5SPYDawH4DNlWeTMnqBEwfZap7wu79zJkZYdCaegzabb/FxFSu0+21djZbq4+PdtsxIqmg8pObu2s7z+BqC0iM5z01deygAfgP4NRzmQqvECiDmjKWxXZlzQNPxnlu3MJZMrfDXTSzDeIBph1YOIag=="; // Private key from appendix B
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(
                new PKCS8EncodedKeySpec(Base64.decodeBase64(privateK)));
 
 
        String jwt = JWT.create()
                .withIssuedAt(new Date())
                .withJWTId(UUID.randomUUID().toString())
                .withSubject(subject)
                .withIssuer(issuer)
                .withAudience(audience)
                .withClaim("resource_id", resourceId)
                .withClaim("email", email)
                .withClaim("first_name", firstName)
                .withClaim("middle_name", middleName)
                .withClaim("last_name", lastName)
                .withExpiresAt(new Date(System.currentTimeMillis()+5*60*1000))
                .sign(Algorithm.RSA256(null, privateKey));
 
        System.out.println(jwt);
    }
}
```

# Example 2. Validate a SNS Launch message
This example is more complicated, mostly because the auth0 JWT library has no helper method for selecting the right algorithm from the JWT header.

```java
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.codec.binary.Base64;
 
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
 
public class JwtProviderExample {
    public static void main(String[] args) throws Exception {
        String token = args[0];
 
        // Get the algorithm name from the JWT.
        String algorithmName = JWT.decode(token).getAlgorithm();
        // Get the issuer name from the JWT.
        String issuer = JWT.decode(token).getIssuer();
 
        // Lookup the issuer.
        String publicK = getPublicKeyForIssuer(issuer); // Public key from appendix A
 
        // Get the algorithm from the public key and algorithm name.
        Algorithm algorithm = getAlgorithm(publicK, algorithmName);
 
        // Decode and verify the token.
        DecodedJWT jwt = JWT.require(algorithm)
                .withAudience("audience.nl") // Make sure to require yourself to be the audience.
                .build()
                .verify(token);
 
        // Read the parameters from the jwt token.
        String subject = jwt.getSubject();
        String resourceId = jwt.getClaim("resource_id").asString();
        String email = jwt.getClaim("email").asString();
        String firstName = jwt.getClaim("first_name").asString();
        String middleName = jwt.getClaim("middle_name").asString();
        String lastName = jwt.getClaim("last_name").asString();
 
        System.out.println(String.format("The SNS launch recieved the user with id %s for resource %s, the user email is %s, the user is known as %s %s %s.",
                subject,
                resourceId,
                email,
                firstName,
                middleName,
                lastName));
    }
 
    /**
     * This method should lookup the public key configured with the issuer from the configuration
     * and / or persistent storage.
     *
     * @param issuer the issuer from the JWT token.
     * @return a public key encoded as String
     */
    private static String getPublicKeyForIssuer(String issuer) {
        // Return the test key from Appendix A.
        return "..." ;
    }
 
    /**
     * Unfortunately, this implementation of JWT has no helper method for selecting the right
     * algorithm from the header. The public key must match the algorithm type (RSA or EC), but
     * the size of the hash algorithm can vary.
     *
     * @param publicKey
     * @param algorithmName
     * @return in instance of the {@link Algorithm} class.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws IllegalArgumentException if the algorithmName is not one of RS{256,384,512} or ES{256,384,512}
     */
    private static Algorithm getAlgorithm(String publicKey, String algorithmName) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalArgumentException {
        switch (algorithmName) {
            case "RS256": {
                return Algorithm.RSA256(getRsaPublicKey(publicKey), null);
            }
            case "RS384": {
                return Algorithm.RSA384(getRsaPublicKey(publicKey), null);
            }
            case "RS512": {
                return Algorithm.RSA512(getRsaPublicKey(publicKey), null);
            }
            case "ES256": {
                return Algorithm.ECDSA256(getEcPublicKey(publicKey), null);
            }
            case "ES384": {
                return Algorithm.ECDSA384(getEcPublicKey(publicKey), null);
            }
            case "ES512": {
                return Algorithm.ECDSA512(getEcPublicKey(publicKey), null);
            }
            default:
                throw new IllegalArgumentException(String.format("Unsupported algorithm %s", algorithmName));
        }
 
    }
 
    /**
     * Parses a public key to an instance of {@link ECPublicKey}.
     *
     * @param publicKey the string representation of the public key.
     * @return an instance of {@link ECPublicKey}.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private static ECPublicKey getEcPublicKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return (ECPublicKey) keyFactory.generatePublic(
                new X509EncodedKeySpec(Base64.decodeBase64(publicKey)));
    }
 
    /**
     * Parses a public key to an instance of {@link RSAPublicKey}.
     *
     * @param publicKey the string representation of the public key.
     * @return an instance of {@link RSAPublicKey}.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private static RSAPublicKey getRsaPublicKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) keyFactory.generatePublic(
                new X509EncodedKeySpec(Base64.decodeBase64(publicKey)));
    }
}
```

### Example 3: Generate a RSA key pair

```java
import java.security.*;
import static org.apache.commons.codec.binary.Base64.encodeBase64String;
 
public class RsaKeyPairGenerator {
 
    public static void main(String[] args) throws Exception {
        new RsaKeyPairGenerator().generate();
    }
 
    public void generate() throws NoSuchAlgorithmException {
        // Create a new generator
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        // Set the key size
        generator.initialize(2024);
        // Generate a pair
        KeyPair keyPair = generator.generateKeyPair();
        // Output the public key as base64
        String publicK = encodeBase64String(keyPair.getPublic().getEncoded());
        // Output the private key as base64
        String privateK = encodeBase64String(keyPair.getPrivate().getEncoded());
 
        System.out.println(publicK);
        System.out.println(privateK);
    }
}
```

# Example 4: Generate a EC key pair

```java
import java.security.*;
import static org.apache.commons.codec.binary.Base64.encodeBase64String;
 
public class EcKeyPairGenerator {
 
    public static void main(String[] args) throws Exception {
        new EcKeyPairGenerator().generate();
    }
 
    public void generate() throws NoSuchAlgorithmException {
        // Create a new generator
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        // Set the key size and random
        generator.initialize(256, random);
        // Generate a pair
        KeyPair keyPair = generator.generateKeyPair();
        // Output the public key as base64
        String publicK = encodeBase64String(keyPair.getPublic().getEncoded());
        // Output the private key as base64
        String privateK = encodeBase64String(keyPair.getPrivate().getEncoded());
 
        System.out.println(publicK);
        System.out.println(privateK);
    }
}
```
