package com.tour.customerservice.service.impl;

import com.tour.customerservice.model.Customer;
import com.tour.customerservice.service.CircuitBreakerService;
import com.tour.customerservice.service.CustomerService;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

@Service
public class CircuitBreakerServiceImpl implements CircuitBreakerService {
    private static final Logger logger = LoggerFactory.getLogger(CircuitBreakerServiceImpl.class);
    private static final String CIRCUIT_BREAKER_INSTANCE = "customerService";

    @Autowired
    private CustomerService customerService;

    @Override
    @CircuitBreaker(name = CIRCUIT_BREAKER_INSTANCE, fallbackMethod = "executeWithCircuitBreakerFallback")
    public <T> T executeWithCircuitBreaker(Supplier<T> operation, Supplier<T> fallback) {
        return operation.get();
    }

    public <T> T executeWithCircuitBreakerFallback(Supplier<T> operation, Supplier<T> fallback, Exception e) {
        logger.error("Circuit breaker đã mở do lỗi: {}", e.getMessage());
        return fallback.get();
    }

    @Override
    @CircuitBreaker(name = CIRCUIT_BREAKER_INSTANCE, fallbackMethod = "findCustomerByEmailFallback")
    public Customer findCustomerByEmail(String email) {
        return customerService.findByEmail(email);
    }

    public Customer findCustomerByEmailFallback(String email, Exception e) {
        logger.error("Không thể tìm khách hàng theo email {}: {}", email, e.getMessage());
        Customer fallbackCustomer = new Customer();
        fallbackCustomer.setEmail(email);
        fallbackCustomer.setName("Temporary User");
        return fallbackCustomer;
    }

    @Override
    @CircuitBreaker(name = CIRCUIT_BREAKER_INSTANCE, fallbackMethod = "findCustomerByPhoneFallback")
    public Customer findCustomerByPhone(String phone) {
        return customerService.findByPhone(phone);
    }

    public Customer findCustomerByPhoneFallback(String phone, Exception e) {
        logger.error("Không thể tìm khách hàng theo số điện thoại {}: {}", phone, e.getMessage());
        Customer fallbackCustomer = new Customer();
        fallbackCustomer.setPhone(phone);
        fallbackCustomer.setName("Temporary User");
        return fallbackCustomer;
    }

    @Override
    @CircuitBreaker(name = CIRCUIT_BREAKER_INSTANCE, fallbackMethod = "findAllCustomersFallback")
    public List<Customer> findAllCustomers() {
        return customerService.findAllCustomers();
    }

    public List<Customer> findAllCustomersFallback(Exception e) {
        logger.error("Không thể lấy danh sách khách hàng: {}", e.getMessage());
        return new ArrayList<>();
    }

    @Override
    @CircuitBreaker(name = CIRCUIT_BREAKER_INSTANCE, fallbackMethod = "updateCustomerFallback")
    public Customer updateCustomer(String token, Customer customer) {
        return customerService.updateCustomer(token, customer);
    }

    public Customer updateCustomerFallback(String token, Customer customer, Exception e) {
        logger.error("Không thể cập nhật thông tin khách hàng: {}", e.getMessage());
        return customer; // Trả về thông tin khách hàng chưa cập nhật
    }

    @Override
    @CircuitBreaker(name = CIRCUIT_BREAKER_INSTANCE, fallbackMethod = "registerCustomerFallback")
    public Customer registerCustomer(Customer customer) {
        return customerService.registerCustomer(customer);
    }

    public Customer registerCustomerFallback(Customer customer, Exception e) {
        logger.error("Không thể đăng ký khách hàng: {}", e.getMessage());
        throw new RuntimeException("Hệ thống tạm thời không khả dụng, vui lòng thử lại sau", e);
    }

    @Override
    @CircuitBreaker(name = CIRCUIT_BREAKER_INSTANCE, fallbackMethod = "generateTokensFallback")
    public Map<String, String> generateTokens(UserDetails userDetails) {
        return customerService.generateTokens(userDetails);
    }

    public Map<String, String> generateTokensFallback(UserDetails userDetails, Exception e) {
        logger.error("Không thể tạo tokens: {}", e.getMessage());
        return Collections.singletonMap("message", "Hệ thống xác thực tạm thời không khả dụng");
    }
}