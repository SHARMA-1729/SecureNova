
package com.securenova.aichat.config;

import java.util.function.Consumer;


import java.time.Duration;


import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // Add PKCE and Auth0 API audience to authorization requests
    @Bean
    public DefaultOAuth2AuthorizationRequestResolver authorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository,
            @Value("${app.auth0.audience}") String apiAudience) {

        DefaultOAuth2AuthorizationRequestResolver resolver =
                new DefaultOAuth2AuthorizationRequestResolver(
                        clientRegistrationRepository,
                        "/oauth2/authorization"
                );

        Consumer<OAuth2AuthorizationRequest.Builder> pkceCustomizer =
                OAuth2AuthorizationRequestCustomizers.withPkce();

        resolver.setAuthorizationRequestCustomizer(builder -> {

            // Generate PKCE code verifier and S256 challenge
            pkceCustomizer.accept(builder);

            // Request token for SecureNova custom API
            builder.additionalParameters(params ->
                    params.put("audience", apiAudience)
            );
        });

        return resolver;
    }

    // Filter chain 1: Secure REST APIs
    @Bean
    @Order(1)
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http)
            throws Exception {

        http
            .securityMatcher(
                    "/chat", "/chat/**",
                    "/admin", "/admin/**"
            )

            .csrf(AbstractHttpConfigurer::disable)

            .sessionManagement(session ->
                    session.sessionCreationPolicy(
                            SessionCreationPolicy.STATELESS
                    )
            )

            .authorizeHttpRequests(authorize -> authorize

                // User-level access
                .requestMatchers("/chat", "/chat/**")
                .hasAuthority("SCOPE_read.ai-data")

                // Admin-level access
                .requestMatchers("/admin", "/admin/**")
                .hasAuthority("SCOPE_write:admin")

                .anyRequest().authenticated()
            )

            .oauth2ResourceServer(oauth2 ->
                    oauth2.jwt(Customizer.withDefaults())
            );

        return http.build();
    }

    // Filter chain 2: Human user login
    @Bean
    @Order(2)
    public SecurityFilterChain webSecurityFilterChain(
            HttpSecurity http,
            DefaultOAuth2AuthorizationRequestResolver authorizationRequestResolver)
            throws Exception {

        http
            .authorizeHttpRequests(authorize -> authorize

                .requestMatchers(
                        "/",
                        "/error",
                        "/oauth2/**",
                        "/login/**",
                        "/css/**",
                        "/js/**"
                ).permitAll()

                .anyRequest().authenticated()
            )

            .oauth2Login(oauth2 -> oauth2

                .authorizationEndpoint(endpoint ->
                        endpoint.authorizationRequestResolver(
                                authorizationRequestResolver
                        )
                )
            )

            .logout(logout ->
                    logout.logoutSuccessUrl("/")
            );

        return http.build();
    }
    
    
    
    
    
    
    @Bean
    JwtDecoder jwtDecoder(
            @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuerUri,
            @Value("${app.auth0.audience}") String audience) {

        NimbusJwtDecoder decoder =
                NimbusJwtDecoder.withIssuerLocation(issuerUri).build();

        OAuth2TokenValidator<Jwt> audienceValidator = jwt -> {
            if (jwt.getAudience().contains(audience)) {
                return OAuth2TokenValidatorResult.success();
            }

            return OAuth2TokenValidatorResult.failure(
                    new OAuth2Error(
                            "invalid_token",
                            "Required API audience is missing",
                            null
                    )
            );
        };

        OAuth2TokenValidator<Jwt> validator =
                new DelegatingOAuth2TokenValidator<>(
                        new JwtTimestampValidator(Duration.ZERO),
                        new JwtIssuerValidator(issuerUri),
                        audienceValidator
                );

        decoder.setJwtValidator(validator);
        

        return decoder;
        
    }
    
    
}


