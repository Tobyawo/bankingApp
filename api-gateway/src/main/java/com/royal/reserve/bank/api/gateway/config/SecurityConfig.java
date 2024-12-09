package com.royal.reserve.bank.api.gateway.config;

import com.auth0.jwk.Jwk;
import com.auth0.jwt.algorithms.Algorithm;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.server.WebFilter;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import reactor.core.publisher.Mono;

/**
 * Configuration class for security settings and JWT token handling.
 */
@Configuration
@EnableWebFluxSecurity
@Getter
public class SecurityConfig {
    @Value("${encodedJwt}")
    private String encodedJwt;

    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private String jwkSetUri;


    @Value("${auth.service.secret}")
    private String authServiceSecret; // Secret for the Auth service JWTs

    private String jwtToken;

    /**
     * Configures the security filters and rules for the server.
     *
     * @param serverHttpSecurity the ServerHttpSecurity object to configure
     * @return the configured SecurityWebFilterChain object
     * @throws IOException                if an I/O error occurs while reading the public key
     * @throws JwkException               if an error occurs while fetching the JSON Web Key from the JwkProvider
     */

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity serverHttpSecurity, RSAPublicKey publicKey) {
        serverHttpSecurity
                .csrf().disable()
                .authenticationManager(customAuthenticationManager(publicKey))
                .authorizeExchange(exchange ->
                        exchange.pathMatchers("/eureka/**", "/discovery-server/**", "/gm-access/**", "/gm-user/**", "/actuator/**")
                                .permitAll()
                                .anyExchange()
                                .authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.publicKey(publicKey)));

        return serverHttpSecurity.build();
    }


    @Bean
    public ReactiveAuthenticationManager customAuthenticationManager(RSAPublicKey publicKey) {
        return token -> {
            try {
                DecodedJWT decodedJWT = JWT.decode(token.getCredentials().toString());
                String issuer = decodedJWT.getIssuer();

                if ("get4me".equals(issuer)) {
                    // Validate Auth service JWT using symmetric key
                    Algorithm algorithm = Algorithm.HMAC256(authServiceSecret);
                    JWT.require(algorithm).withIssuer("get4me").build().verify(decodedJWT);
                } else {
                    // Validate other JWTs using public key
                    Algorithm algorithm = Algorithm.RSA256(publicKey, null);
                    JWT.require(algorithm).build().verify(decodedJWT);
                }

                // If validation succeeds, return an authenticated token
                return Mono.just(new UsernamePasswordAuthenticationToken(decodedJWT.getSubject(), token, Collections.emptyList()));
            } catch (Exception e) {
                return Mono.error(new BadCredentialsException("Invalid token", e));
            }
        };
    }

    /**
     * Loads the RSA public key from the JSON Web Key Set (JWK Set) URL.
     *
     * @param token the DecodedJWT object representing the decoded JWT
     * @return the RSAPublicKey object loaded from the JWK Set
     * @throws JwkException            if an error occurs while fetching the JSON Web Key from the JwkProvider
     * @throws MalformedURLException  if the JWK Set URL is malformed
     */
    @Bean
    public RSAPublicKey publicKey() throws IOException, JwkException {
        // Fetch and load the public key from the JWK Set URI
        final DecodedJWT jwt = JWT.decode(encodedJwt);
        JwkProvider provider = new UrlJwkProvider(new URL(jwkSetUri));
        Jwk jwk = provider.get(jwt.getKeyId()); // Replace `null` with an actual key ID if needed
        return (RSAPublicKey) jwk.getPublicKey();
    }

    /**
     * Creates a WebFilter for extracting the JWT token from the request headers.
     *
     * @return the created WebFilter object
     */
    @Bean
    WebFilter jwtFilter() {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String authorizationHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                jwtToken = authorizationHeader.substring(7);
            }
            return chain.filter(exchange);
        };
    }



}



//
//1. Multiple Token Validation Mechanisms
//Symmetric Validation for Internal JWTs
//Use the secret key shared by the authentication service to validate the tokens.
//The gateway validates tokens signed with HMAC (e.g., HMAC256) using the same secret.
//Asymmetric Validation for OAuth JWTs
//Use the public key(s) published by the OAuth provider via their JWKS (JSON Web Key Set) endpoint, typically located at .well-known/jwks.json.
//The gateway fetches the public keys from the JWKS endpoint and uses them to validate tokens signed with asymmetric algorithms (e.g., RS256).

//2. Implementation Steps
//Distinguish Between Token Sources:
//
//Include a claim in the JWT (e.g., iss or aud) to identify the source (internal service vs. OAuth).
