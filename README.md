# Java RESTful API Demo

This is a simple Java RESTful API application built using Spring Boot.

## Setup
- Clone the repository

```sh
git clone https://github.com/mrnobody7-a/java-restful-api.git
cd java-restful-api
```
- Run the application
```sh
mvn spring-boot:run
```

## Features

- Home endpoint: `GET /`
- User profile endpoint: `GET /user/{username}`
- Data reception endpoint: `POST /data`
- User registration endpoint: `POST /register`
- User login endpoint: `POST /login`
- Password update endpoint: `PUT /update-password`

## Security Vulnerabilities

1. **Cross-Site Scripting (XSS)**:
   - The `username` and `data` inputs are not sanitized, making the application vulnerable to XSS attacks.
   - Example: Entering `<script>alert('XSS')</script>` as a username could execute the script in the user's browser.

2. **Cross-Site Request Forgery (CSRF)**:
   - The application lacks CSRF protection for forms.

3. **SQL Injection**:
   - Though there are no direct SQL queries in this snippet, any user input directly used in SQL queries without sanitization could lead to SQL Injection.

4. **Information Disclosure**:
   - Exposing detailed error messages to users can lead to information disclosure.

5. **Password Storage**:
   - Storing passwords in plain text is highly insecure.

## Secure Coding Practices

1. **Input Validation and Sanitization**:
   - Always validate and sanitize user inputs to prevent XSS, SQL injection, and other injection attacks.
   ```java
   import org.springframework.web.util.HtmlUtils;

   @GetMapping("/user/{username}")
   public String showUserProfile(@PathVariable String username) {
       return "User: " + HtmlUtils.htmlEscape(username);
   }
2. **CSRF Protection**
- Implement CSRF tokens for forms using Spring Security.

```java
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable(); // Only disable for testing, enable in production
    }
}
```
3. **Avoid Sensitive Information Exposure**
   - Configure proper error handling and logging.

```java
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestControllerAdvice
public class GlobalExceptionHandler {
    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(Exception.class)
    public String handleException(Exception e) {
        logger.error("Error occurred: ", e);
        return "An error occurred. Please try again later.";
    }
}
```
4. **Password Storage**
   - Use a strong hashing algorithm like BCrypt to store passwords.
  
```java
import org.springframework.security.crypto.bcrypt.BCrypt;

@PostMapping("/register")
public String registerUser(@RequestParam String username, @RequestParam String password) {
    if (users.containsKey(username)) {
        throw new ResponseStatusException(HttpStatus.CONFLICT, "Username already exists");
    }
    String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt());
    users.put(username, hashedPassword);
    return "User registered successfully";
}

@PostMapping("/login")
public String loginUser(@RequestParam String username, @RequestParam String password) {
    String storedPassword = users.get(username);
    if (storedPassword == null || !BCrypt.checkpw(password, storedPassword)) {
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
    }
    return "Login successful";
}

@PutMapping("/update-password")
public String updatePassword(@RequestParam String username, @RequestParam String oldPassword, @RequestParam String newPassword) {
    String storedPassword = users.get(username);
    if (storedPassword == null || !BCrypt.checkpw(oldPassword, storedPassword)) {
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
    }
    String hashedPassword = BCrypt.hashpw(newPassword, BCrypt.gensalt());
    users.put(username, hashedPassword);
    return "Password updated successfully";
}
```
## Best Practices and Guidelines

1. **Regular Code Reviews**:
   - Conduct regular manual code reviews to identify potential security vulnerabilities and code quality issues that automated tools might miss.

2. **Static Code Analysis**:
   - Integrate static code analysis tools like SonarQube or Checkmarx SAST into your CI/CD pipeline to continuously monitor code quality and security.

3. **Dependency Management**:
   - Keep your dependencies up to date and use tools like Dependabot to get notifications about vulnerabilities in your dependencies.

4. **Secure Configuration**:
   - Ensure secure configuration of your application, including using HTTPS, secure headers, and environment variables for sensitive data.

5. **Security Training**:
   - Provide regular security training for your development team to stay updated on the latest security best practices and vulnerabilities.

6. **Automated Testing**:
   - Implement automated testing for your application, including unit tests, integration tests, and security tests to ensure the reliability and security of your code.
