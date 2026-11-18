package com.logicwarez.authz.bff;

import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/** Access token firmati con una chiave dei test, al posto di quelli dello IAM. */
final class TestTokens {

    private static final RSAKey KEY;

    static {
        try {
            KEY = new RSAKeyGenerator(2048).keyID("test").generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private TestTokens() {
    }

    static JwtDecoder decoder() {
        try {
            return NimbusJwtDecoder.withPublicKey(KEY.toRSAPublicKey()).build();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    static String token(String username, Instant expiresAt) {
        try {
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("test").build(),
                    new JWTClaimsSet.Builder()
                            .claim("preferred_username", username)
                            .claim("name", "Nome " + username)
                            .claim("azp", "tools")
                            .issueTime(Date.from(expiresAt.minusSeconds(300)))
                            .expirationTime(Date.from(expiresAt))
                            .build());
            jwt.sign(new RSASSASigner(KEY));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    static String token(String username) {
        return token(username, Instant.now().plusSeconds(300));
    }

    static final String ISSUER = "https://iam.test/realms/test";
    static final String CLIENT = "bff-gateway";

    /** Decoder dei logout token con la chiave dei test e la validazione vera del BFF. */
    static JwtDecoder logoutDecoder() {
        try {
            NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(KEY.toRSAPublicKey()).validateType(false).build();
            decoder.setJwtValidator(BackChannelLogout.validator(ISSUER, CLIENT));
            return decoder;
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Logout token di OIDC Back-Channel Logout; sub o sid possono essere null. */
    static JWTClaimsSet.Builder logoutClaims(String sub, String sid) {
        Instant now = Instant.now();
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER).audience(CLIENT).issueTime(Date.from(now)).expirationTime(Date.from(now.plusSeconds(120)))
                .jwtID(UUID.randomUUID().toString())
                .claim("events", Map.of(BackChannelLogout.EVENT, Map.of()));
        if (sub != null) {
            claims.subject(sub);
        }
        if (sid != null) {
            claims.claim("sid", sid);
        }
        return claims;
    }

    static String sign(JWTClaimsSet claims) {
        try {
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("test")
                    .type(new JOSEObjectType("logout+jwt")).build(), claims);
            jwt.sign(new RSASSASigner(KEY));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Firmato con un'altra chiave: la firma non e' valida. */
    static String signWithOtherKey(JWTClaimsSet claims) {
        try {
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("test").build(), claims);
            jwt.sign(new RSASSASigner(new RSAKeyGenerator(2048).generate()));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }
}
