

package com.securenova.aichat.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin")
public class AdminController {

    @GetMapping
    public AdminResponse admin() {

        return new AdminResponse(
                "Welcome to the SecureNova Admin API",
                "success"
        );
    }

    public record AdminResponse(String message, String status) {
    }
}
