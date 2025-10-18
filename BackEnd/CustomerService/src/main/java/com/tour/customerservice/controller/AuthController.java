package com.tour.customerservice.controller;

import com.tour.customerservice.dto.CustomerLoginDTO;
import com.tour.customerservice.dto.CustomerResponseDTO;
import com.tour.customerservice.model.Customer;
import com.tour.customerservice.repository.CustomerRepository;
import com.tour.customerservice.service.CircuitBreakerService;
import com.tour.customerservice.service.CustomerService;
import com.tour.customerservice.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.Map;
import java.util.Optional;

@RestController
@CrossOrigin(origins = "*")
@RequestMapping("/customer/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private CustomerService customUserDetailsService;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private CustomerService customerService;

    @Autowired
    private CircuitBreakerService circuitBreakerService;

    private final CustomerRepository customerRepository;

    @PostMapping("/login")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody CustomerLoginDTO customer) {
        Optional<Customer> customerOpt = customerRepository.findByEmail(customer.getEmail());

        if (customerOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Tài khoản không tồn tại");
        }

        Customer foundCustomer = customerOpt.get();

        // ⚠️ Nếu tài khoản đăng ký bằng Google, từ chối đăng nhập bằng password
        if (foundCustomer.getAuthProvider() == Customer.AuthProvider.GOOGLE) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Tài khoản này chỉ hỗ trợ đăng nhập bằng Google");
        }

        // ✅ Chỉ cho phép khi là LOCAL
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(customer.getEmail(), customer.getPassword()));

        final UserDetails userDetails = customUserDetailsService.loadUserByUsername(customer.getEmail());
        Map<String, String> tokens = circuitBreakerService.generateTokens(userDetails);

        return ResponseEntity.ok(tokens);
    }

    public AuthController(CustomerRepository customerRepository) {
        this.customerRepository = customerRepository;
    }

    @GetMapping("/login/google")
    public ResponseEntity<?> oauth2Success(Authentication authentication) {
        if (authentication == null || !(authentication instanceof OAuth2AuthenticationToken)) {
            return ResponseEntity.badRequest().body("Google authentication failed: No authentication object");
        }

        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        OAuth2User oAuth2User = token.getPrincipal();
        Map<String, Object> attributes = oAuth2User.getAttributes();

        String email = (String) attributes.get("email");
        String name = (String) attributes.getOrDefault("name", "Unknown");
        String phone = (String) attributes.getOrDefault("phone", ""); // thường không có "phone"

        if (email == null || email.isEmpty()) {
            return ResponseEntity.badRequest().body("Google account missing email");
        }

        // Tìm hoặc tạo Customer
        Customer customer = customerRepository.findByEmail(email).orElseGet(() -> {
            Customer newCustomer = new Customer();
            newCustomer.setEmail(email);
            newCustomer.setName(name);
            newCustomer.setPhone(phone);
            newCustomer.setRole(Customer.Role.CUSTOMER);
            newCustomer.setPassword(""); // vì dùng Google nên không cần mật khẩu
            newCustomer.setAuthProvider(Customer.AuthProvider.GOOGLE);
            return customerRepository.save(newCustomer);
        });

        // Load lại UserDetails để tạo token
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(customer.getEmail());

        // Trả về access + refresh token, sử dụng circuit breaker
        Map<String, String> tokens = circuitBreakerService.generateTokens(userDetails);
        return ResponseEntity.ok(tokens);
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerCustomer(@RequestBody Customer customer) {
        try {
            Customer registeredCustomer = circuitBreakerService.registerCustomer(customer);

            // Chuyển sang DTO để trả về
            CustomerResponseDTO responseDTO = new CustomerResponseDTO();
            responseDTO.setId(registeredCustomer.getId());
            responseDTO.setName(registeredCustomer.getName());
            responseDTO.setEmail(registeredCustomer.getEmail());
            responseDTO.setPhone(registeredCustomer.getPhone());
            responseDTO.setCreatedAt(registeredCustomer.getCreatedAt());
            responseDTO.setRole(registeredCustomer.getRole());
            responseDTO.setAuthProvider(registeredCustomer.getAuthProvider());

            return ResponseEntity.ok(responseDTO);

        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");

        if (refreshToken == null || refreshToken.isEmpty()) {
            return ResponseEntity.badRequest().body("Missing refresh token");
        }

        try {
            // Giải mã token và lấy username (email)
            String email = jwtUtil.extractUsername(refreshToken);

            // Tìm người dùng
            Customer customer = circuitBreakerService.findCustomerByEmail(email);
            if (customer == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User not found");
            }

            // So sánh refreshToken gửi lên với token lưu trong DB
            if (!refreshToken.equals(customer.getRefreshToken())) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid refresh token");
            }

            // Kiểm tra hạn token
            if (jwtUtil.isTokenExpired(refreshToken)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Refresh token expired");
            }

            // Tạo token mới
            UserDetails userDetails = new org.springframework.security.core.userdetails.User(
                    customer.getEmail(), customer.getPassword(), new ArrayList<>());
            Map<String, String> tokens = circuitBreakerService.generateTokens(userDetails);

            return ResponseEntity.ok(tokens);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid refresh token format");
        }
    }
}