
package com.securenova.aichat.controller;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/chat")
public class ChatController {

    @PostMapping
    public ChatResponse chat(@RequestBody ChatRequest request) {

        if (request.message() == null || request.message().isBlank()) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Message cannot be empty"
            );
        }

        // Temporary response for the security demonstration.
        // No external LLM is connected yet.
        String response = "SecureNova received your message: "
                + request.message();

        return new ChatResponse(response, "success");
    }

    // Incoming request structure
    public record ChatRequest(String message) {
    }

    // Outgoing response structure
    public record ChatResponse(String response, String status) {
    }
}
