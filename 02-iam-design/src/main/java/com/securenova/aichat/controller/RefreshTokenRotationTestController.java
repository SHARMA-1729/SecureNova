
package com.securenova.aichat.controller;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Temporary SecureNova Project 4 test utility.
 *
 * Demonstrates:
 * 1. Successful Auth0 refresh-token rotation.
 * 2. Replacement refresh-token issuance.
 * 3. Rejection when the original refresh token is replayed.
 *
 * Raw tokens and secrets are never logged or returned.
 */
@RestController
public class RefreshTokenRotationTestController {

    private static final String REGISTRATION_ID = "auth0";

    private static final String TEST_PATH =
            "/internal/auth0/refresh-token-rotation-test";

    private final OAuth2AuthorizedClientRepository authorizedClientRepository;
    private final ClientRegistrationRepository registrationRepository;
    private final boolean testEnabled;

    private final AtomicBoolean testStarted = new AtomicBoolean(false);

    public RefreshTokenRotationTestController(
            OAuth2AuthorizedClientRepository authorizedClientRepository,
            ClientRegistrationRepository registrationRepository,
            @Value("${app.auth0.refresh-token-rotation-test-enabled:false}")
            boolean testEnabled) {

        this.authorizedClientRepository = authorizedClientRepository;
        this.registrationRepository = registrationRepository;
        this.testEnabled = testEnabled;
    }

    /**
     * Display a protected one-time test form.
     * The form includes Spring Security's CSRF token.
     */
    @GetMapping(
            value = TEST_PATH,
            produces = MediaType.TEXT_HTML_VALUE
    )
    public ResponseEntity<String> showTestPage(
    		@RequestAttribute("_csrf")
            CsrfToken csrfToken) {

        if (!testEnabled) {
            return ResponseEntity.notFound().build();
        }

        String csrfName = escapeHtml(csrfToken.getParameterName());
        String csrfValue = escapeHtml(csrfToken.getToken());

        String html = """
                <!DOCTYPE html>
                <html>
                <head>
                    <title>SecureNova Refresh Token Rotation Test</title>
                </head>
                <body>
                    <h2>SecureNova - Auth0 Refresh Token Rotation Test</h2>

                    <p>This is a controlled, one-time security test.</p>

                    <p>
                        It will exchange the current refresh token,
                        then attempt to reuse the original token.
                    </p>

                    <p>
                        Auth0 may revoke the refresh-token family
                        after detecting reuse. You may need to log in again.
                    </p>

                    <form method="post"
                          action="%s">

                        <input type="hidden"
                               name="%s"
                               value="%s">

                        <button type="submit">
                            Run Refresh Token Rotation Test
                        </button>
                    </form>
                </body>
                </html>
                """.formatted(TEST_PATH, csrfName, csrfValue);

        return ResponseEntity.ok()
                .contentType(MediaType.TEXT_HTML)
                .body(html);
    }

    /**
     * Execute the rotation and old-token replay test.
     */
    @PostMapping(
            value = TEST_PATH,
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<Map<String, Object>> runRotationTest(
            Authentication authentication,
            HttpServletRequest request) {

        if (!testEnabled) {
            return safeResponse(
                    HttpStatus.NOT_FOUND,
                    "Test endpoint disabled."
            );
        }

        if (authentication == null
                || !authentication.isAuthenticated()
                || "anonymousUser".equals(authentication.getName())) {

            return safeResponse(
                    HttpStatus.UNAUTHORIZED,
                    "An authenticated user session is required."
            );
        }

        ClientRegistration registration =
                registrationRepository.findByRegistrationId(
                        REGISTRATION_ID
                );

        if (registration == null) {
            return safeResponse(
                    HttpStatus.INTERNAL_SERVER_ERROR,
                    "Auth0 client registration was not found."
            );
        }

        OAuth2AuthorizedClient authorizedClient =
                authorizedClientRepository.loadAuthorizedClient(
                        REGISTRATION_ID,
                        authentication,
                        request
                );

        if (authorizedClient == null
                || authorizedClient.getRefreshToken() == null) {

            return safeResponse(
                    HttpStatus.CONFLICT,
                    "No refresh token is stored. Sign out, sign in again "
                            + "after enabling offline_access, and retry."
            );
        }

        // Prevent accidental double submissions.
        if (!testStarted.compareAndSet(false, true)) {
            return safeResponse(
                    HttpStatus.CONFLICT,
                    "This test has already been attempted. "
                            + "A fresh login and application restart are required."
            );
        }

        String originalRefreshToken =
                authorizedClient.getRefreshToken().getTokenValue();

        String timestamp = Instant.now().toString();

        System.out.println();
        System.out.println("==================================================");
        System.out.println("SecureNova - Auth0 Refresh Token Rotation Test");
        System.out.println("==================================================");

        try {

            // ------------------------------------------------
            // FIRST EXCHANGE: ORIGINAL TOKEN
            // ------------------------------------------------

            System.out.println("Performing initial refresh-token exchange...");

            ExchangeResult firstExchange = exchangeRefreshToken(
                    registration,
                    originalRefreshToken
            );

            System.out.println(
                    "Initial exchange HTTP status: "
                            + firstExchange.httpStatus()
            );

            boolean replacementIssued =
                    firstExchange.httpStatus() == 200
                    && firstExchange.refreshToken() != null
                    && !firstExchange.refreshToken().isBlank()
                    && !firstExchange.refreshToken()
                            .equals(originalRefreshToken);

            System.out.println(
                    "Replacement refresh token issued: "
                            + replacementIssued
            );

            if (!replacementIssued) {

                String errorCode = safeErrorCode(
                        firstExchange.errorCode()
                );

                Map<String, Object> evidence = createEvidence(
                        timestamp,
                        firstExchange.httpStatus(),
                        false,
                        0,
                        errorCode,
                        false,
                        "FAIL"
                );

                saveEvidence(evidence);

                System.out.println("Initial token exchange failed.");
                System.out.println("OAuth error code: " + errorCode);
                System.out.println("RESULT: FAIL");

                return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                        .body(evidence);
            }

            String replacementRefreshToken =
                    firstExchange.refreshToken();

            // ------------------------------------------------
            // SECOND EXCHANGE: REPLAY ORIGINAL TOKEN
            // ------------------------------------------------

            System.out.println();
            System.out.println(
                    "Replaying the original refresh token..."
            );

            ExchangeResult replayExchange = exchangeRefreshToken(
                    registration,
                    originalRefreshToken
            );

            String replayError = safeErrorCode(
                    replayExchange.errorCode()
            );

            boolean replayRejected =
                    replayExchange.httpStatus() >= 400
                    && "invalid_grant".equals(replayError);

            System.out.println(
                    "Old refresh token replay HTTP status: "
                            + replayExchange.httpStatus()
            );

            System.out.println(
                    "OAuth error code: " + replayError
            );

            System.out.println(
                    "Old refresh token rejected: " + replayRejected
            );

            String result = replayRejected ? "PASS" : "FAIL";

            Map<String, Object> evidence = createEvidence(
                    timestamp,
                    firstExchange.httpStatus(),
                    true,
                    replayExchange.httpStatus(),
                    replayError,
                    replayRejected,
                    result
            );

            saveEvidence(evidence);

            System.out.println();
            System.out.println("==================================================");
            System.out.println("AUTH0 REFRESH TOKEN ROTATION SUMMARY");
            System.out.println("==================================================");
            System.out.println("Original exchange successful: true");
            System.out.println("Replacement token issued: true");
            System.out.println(
                    "Original token replay rejected: " + replayRejected
            );
            System.out.println("RESULT: " + result);
            System.out.println("==================================================");

            // Release token references as soon as practical.
            originalRefreshToken = null;
            replacementRefreshToken = null;

            return ResponseEntity.ok(evidence);

        } catch (InterruptedException exception) {

            Thread.currentThread().interrupt();

            System.out.println("Test interrupted.");
            System.out.println("RESULT: FAIL");

            return safeResponse(
                    HttpStatus.INTERNAL_SERVER_ERROR,
                    "The token exchange was interrupted."
            );

        } catch (Exception exception) {

            // Never print exception messages or HTTP bodies here.
            // They could contain credential-related information.

            System.out.println(
                    "Test execution error: "
                            + exception.getClass().getSimpleName()
            );

            System.out.println("RESULT: FAIL");

            return safeResponse(
                    HttpStatus.BAD_GATEWAY,
                    "The controlled token exchange could not complete. "
                            + "Review the application configuration."
            );
        }
    }

    /**
     * Send one refresh-token request to Auth0.
     * The response's raw body is parsed in memory only.
     */
    private ExchangeResult exchangeRefreshToken(
            ClientRegistration registration,
            String refreshToken)
            throws IOException, InterruptedException {

        String tokenUri =
                registration.getProviderDetails().getTokenUri();

        String clientId = registration.getClientId();
        String clientSecret = registration.getClientSecret();

        if (tokenUri == null
                || clientId == null
                || clientSecret == null) {

            throw new IllegalStateException(
                    "Incomplete Auth0 client configuration."
            );
        }

        String credentials = clientId + ":" + clientSecret;

        String basicCredentials = Base64.getEncoder().encodeToString(
                credentials.getBytes(StandardCharsets.UTF_8)
        );

        String formBody =
                "grant_type=refresh_token"
                + "&refresh_token="
                + URLEncoder.encode(
                        refreshToken,
                        StandardCharsets.UTF_8
                );

        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(tokenUri))
                .timeout(Duration.ofSeconds(25))
                .header(
                        "Authorization",
                        "Basic " + basicCredentials
                )
                .header(
                        "Content-Type",
                        "application/x-www-form-urlencoded"
                )
                .POST(
                        HttpRequest.BodyPublishers.ofString(
                                formBody,
                                StandardCharsets.UTF_8
                        )
                )
                .build();

        HttpClient httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();

        HttpResponse<String> response = httpClient.send(
                httpRequest,
                HttpResponse.BodyHandlers.ofString()
        );

        String body = response.body();

        String returnedRefreshToken = extractJsonString(
                body,
                "refresh_token"
        );

        String errorCode = extractJsonString(
                body,
                "error"
        );

        return new ExchangeResult(
                response.statusCode(),
                returnedRefreshToken,
                errorCode
        );
    }

    /**
     * Extract one JSON string field without returning or logging
     * the raw token response.
     */
    private String extractJsonString(
            String json,
            String fieldName) {

        if (json == null || json.isBlank()) {
            return null;
        }

        Pattern pattern = Pattern.compile(
                "\"" + Pattern.quote(fieldName)
                        + "\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\""
        );

        Matcher matcher = pattern.matcher(json);

        if (matcher.find()) {
            return matcher.group(1);
        }

        return null;
    }

    /**
     * Only expose simple OAuth error codes.
     */
    private String safeErrorCode(String errorCode) {

        if (errorCode == null
                || !errorCode.matches("[A-Za-z0-9_.-]{1,64}")) {

            return "not_available";
        }

        return errorCode;
    }

    private Map<String, Object> createEvidence(
            String timestamp,
            int firstStatus,
            boolean replacementIssued,
            int replayStatus,
            String oauthError,
            boolean replayRejected,
            String result) {

        Map<String, Object> evidence = new LinkedHashMap<>();

        evidence.put(
                "project",
                "SecureNova"
        );

        evidence.put(
                "task",
                "Project 4 - Task 3: Auth0 Refresh Token Rotation"
        );

        evidence.put(
                "timestamp_utc",
                timestamp
        );

        evidence.put(
                "event_type",
                "REFRESH_TOKEN_ROTATION_AND_REUSE_DETECTION"
        );

        evidence.put(
                "client_registration",
                REGISTRATION_ID
        );

        evidence.put(
                "initial_exchange_http_status",
                firstStatus
        );

        evidence.put(
                "replacement_refresh_token_issued",
                replacementIssued
        );

        evidence.put(
                "old_refresh_token_replay_http_status",
                replayStatus
        );

        evidence.put(
                "old_refresh_token_oauth_error",
                oauthError
        );

        evidence.put(
                "old_refresh_token_replay_rejected",
                replayRejected
        );

        evidence.put(
                "result",
                result
        );

        evidence.put(
                "raw_tokens_logged",
                false
        );

        evidence.put(
                "client_secret_logged",
                false
        );

        evidence.put(
                "implementation_type",
                "REAL AUTH0 TEST TENANT TOKEN ENDPOINT"
        );

        return evidence;
    }

    /**
     * Save only safe test metadata, never token values.
     */
    private void saveEvidence(
            Map<String, Object> evidence) {

        try {

            Path evidenceDirectory = Path.of(
                    System.getProperty("user.dir"),
                    "evidence",
                    "project4",
                    "task3_auth0_hardening"
            );

            Files.createDirectories(evidenceDirectory);

            Path evidenceFile = evidenceDirectory.resolve(
                    "refresh_token_rotation_replay_test.json"
            );

            StringBuilder json = new StringBuilder("{\n");

            int index = 0;

            for (Map.Entry<String, Object> entry
                    : evidence.entrySet()) {

                json.append("  \"")
                        .append(entry.getKey())
                        .append("\": ");

                Object value = entry.getValue();

                if (value instanceof Number
                        || value instanceof Boolean) {

                    json.append(value);

                } else {

                    json.append("\"")
                            .append(
                                    escapeJson(String.valueOf(value))
                            )
                            .append("\"");
                }

                if (++index < evidence.size()) {
                    json.append(",");
                }

                json.append("\n");
            }

            json.append("}\n");

            Files.writeString(
                    evidenceFile,
                    json.toString(),
                    StandardCharsets.UTF_8
            );

            System.out.println(
                    "Safe evidence saved: " + evidenceFile
            );

        } catch (IOException exception) {

            System.out.println(
                    "Evidence save failed: "
                            + exception.getClass().getSimpleName()
            );
        }
    }

    private String escapeJson(String value) {

        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
    }

    private String escapeHtml(String value) {

        return value
                .replace("&", "&amp;")
                .replace("\"", "&quot;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
    }

    private ResponseEntity<Map<String, Object>> safeResponse(
            HttpStatus status,
            String message) {

        Map<String, Object> body = new LinkedHashMap<>();

        body.put("result", "NOT_EXECUTED");
        body.put("message", message);
        body.put("raw_tokens_logged", false);

        return ResponseEntity.status(status).body(body);
    }

    private record ExchangeResult(
            int httpStatus,
            String refreshToken,
            String errorCode) {
    }
}
