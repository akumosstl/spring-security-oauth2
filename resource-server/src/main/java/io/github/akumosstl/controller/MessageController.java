package io.github.akumosstl.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/api")
public class MessageController {

    @GetMapping("/public")
    public String publicEndpoint() {
        return "Hello from public endpoint!";
    }

    @GetMapping("/protected")
    public String protectedEndpoint(Principal principal) {
        return "Hello " + principal.getName() + ", this is a protected endpoint!";
    }
}

