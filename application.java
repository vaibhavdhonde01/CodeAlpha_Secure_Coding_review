package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
@RestController
public class DemoApplication {

    private static Map<String, String> users = new HashMap<>();

    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }

    @GetMapping("/")
    public String home() {
        return "Hello, World!";
    }

    @GetMapping("/user/{username}")
    public String showUserProfile(@PathVariable String username) {
        String user = users.get(username);
        if (user == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found");
        }
        return "User: " + username;
    }

    @PostMapping("/data")
    public String receiveData(@RequestParam String data) {
        return "Received data: " + data;
    }

    @PostMapping("/register")
    public String registerUser(@RequestParam String username, @RequestParam String password) {
        if (users.containsKey(username)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Username already exists");
        }
        users.put(username, password);
        return "User registered successfully";
    }

    @PostMapping("/login")
    public String loginUser(@RequestParam String username, @RequestParam String password) {
        String storedPassword = users.get(username);
        if (storedPassword == null || !storedPassword.equals(password)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }
        return "Login successful";
    }

    @PutMapping("/update-password")
    public String updatePassword(@RequestParam String username, @RequestParam String oldPassword, @RequestParam String newPassword) {
        String storedPassword = users.get(username);
        if (storedPassword == null || !storedPassword.equals(oldPassword)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }
        users.put(username, newPassword);
        return "Password updated successfully";
    }
}
