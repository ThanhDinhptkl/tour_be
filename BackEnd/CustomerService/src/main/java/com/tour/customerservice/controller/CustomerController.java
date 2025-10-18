package com.tour.customerservice.controller;

import com.tour.customerservice.dto.ChangePasswordDTO;
import com.tour.customerservice.dto.CustomerResponseDTO;
import com.tour.customerservice.model.Customer;
import com.tour.customerservice.service.CircuitBreakerService;
import com.tour.customerservice.service.CustomerService;
import com.tour.customerservice.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@CrossOrigin(origins = "*")
@RequestMapping("/customer")
public class CustomerController {

    @Autowired
    private CustomerService customerService;

    @Autowired
    private CircuitBreakerService circuitBreakerService;

    @Autowired
    private JwtUtil jwtUtil;

    private CustomerResponseDTO toDTO(Customer customer) {
        return new CustomerResponseDTO(
                customer.getId(),
                customer.getName(),
                customer.getEmail(),
                customer.getPhone(),
                customer.getRole(),
                customer.getCreatedAt(),
                customer.getAuthProvider());
    }

    @GetMapping("/email/{email}")
    public ResponseEntity<Customer> getCustomerByEmail(@PathVariable String email) {
        Customer customer = circuitBreakerService.findCustomerByEmail(email);
        return ResponseEntity.ok(customer);
    }

    @GetMapping("/phone/{phone}")
    public ResponseEntity<?> getCustomerByPhone(@PathVariable String phone) {
        Customer customer = circuitBreakerService.findCustomerByPhone(phone);
        return ResponseEntity.ok(toDTO(customer));
    }

    @PutMapping("/update")
    public ResponseEntity<?> updateCustomer(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String token,
            @RequestBody Customer customer) {
        try {
            Customer updatedCustomer = circuitBreakerService.updateCustomer(token.replace("Bearer ", ""), customer);
            return ResponseEntity.ok(toDTO(updatedCustomer));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }
    }

    @PostMapping("/changepassword")
    public ResponseEntity<?> changePassword(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String token,
            @RequestBody ChangePasswordDTO request) {
        try {
            customerService.changePassword(token.replace("Bearer ", ""), request.getOldPassword(),
                    request.getNewPassword());
            return ResponseEntity.noContent().build();
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }
    }

    @DeleteMapping("/delete/{id}")
    public ResponseEntity<Void> deleteCustomer(@PathVariable Integer id) {
        customerService.deleteCustomer(id);
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/resetpassword/{id}")
    public ResponseEntity<Void> resetPassword(@PathVariable Integer id) {
        customerService.resetPassword(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/customerlist")
    public ResponseEntity<List<CustomerResponseDTO>> getAllCustomers() {
        List<Customer> customers = circuitBreakerService.findAllCustomers();
        List<CustomerResponseDTO> dtos = customers.stream().map(this::toDTO).collect(Collectors.toList());
        return ResponseEntity.ok(dtos);
    }

    @GetMapping("/profile")
    public ResponseEntity<?> getProfile(@RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        try {
            String email = jwtUtil.extractUsername(token.replace("Bearer ", ""));
            Customer customer = circuitBreakerService.findCustomerByEmail(email);
            if (customer == null) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
            }
            return ResponseEntity.ok(toDTO(customer));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid token");
        }
    }

    // @GetMapping("/customer/dashboard")
    // @PreAuthorize("hasRole('CUSTOMER')")
    // public String customerDashboard() {
    // return "Welcome to Customer Dashboard!";
    // }
    //
    // @GetMapping("/admin/dashboard")
    // @PreAuthorize("hasRole('ADMIN')")
    // public String adminDashboard() {
    // return "Welcome to Admin Dashboard!";
    // }
    //
    // @GetMapping("/guide/dashboard")
    // @PreAuthorize("hasRole('GUIDE')")
    // public String guideDashboard() {
    // return "Welcome to Guide Dashboard!";
    // }
}