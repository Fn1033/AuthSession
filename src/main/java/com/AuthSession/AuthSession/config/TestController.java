package com.AuthSession.AuthSession.config;

import jakarta.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.*;

@RestController
public class TestController {
    @GetMapping("/public")
    public String publicEndpoint() {
        return "This is a public endpoint accessible by anyone.";
    }

    @GetMapping("/user/home")
    public String userHome() {
        return "Welcome, user.";
    }

    @GetMapping("/admin/home")
    public String adminHome() {
        return "Welcome, admin.";
    }

    @PostMapping("/write")
    public String write(HttpSession session,
                        @RequestParam("key") String key,
                        @RequestBody String text) {
        session.setAttribute(key, text);
        return "Session updated.";
    }

    @GetMapping("/read")
    public String read(HttpSession session,
                       @RequestParam("key") String key) {
        String value = (String) session.getAttribute(key);
        return value;
    }
}
