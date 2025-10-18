package com.tour.customerservice.service;

import com.tour.customerservice.model.Customer;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Service cung cấp các phương thức được bảo vệ bởi Circuit Breaker
 */
public interface CircuitBreakerService {
    /**
     * Thực thi một thao tác với circuit breaker
     * 
     * @param operation Thao tác cần thực hiện
     * @param fallback  Thao tác fallback khi circuit breaker mở
     * @param <T>       Kiểu dữ liệu trả về
     * @return Kết quả từ thao tác chính hoặc từ fallback
     */
    <T> T executeWithCircuitBreaker(Supplier<T> operation, Supplier<T> fallback);

    /**
     * Tìm khách hàng theo email với circuit breaker
     * 
     * @param email Email cần tìm
     * @return Customer tìm thấy hoặc fallback
     */
    Customer findCustomerByEmail(String email);

    /**
     * Tìm khách hàng theo số điện thoại với circuit breaker
     * 
     * @param phone Số điện thoại cần tìm
     * @return Customer tìm thấy hoặc fallback
     */
    Customer findCustomerByPhone(String phone);

    /**
     * Lấy danh sách khách hàng với circuit breaker
     * 
     * @return Danh sách khách hàng hoặc danh sách rỗng
     */
    List<Customer> findAllCustomers();

    /**
     * Cập nhật thông tin khách hàng với circuit breaker
     * 
     * @param token    JWT token
     * @param customer Thông tin cập nhật
     * @return Customer sau khi cập nhật hoặc fallback
     */
    Customer updateCustomer(String token, Customer customer);

    /**
     * Đăng ký khách hàng mới với circuit breaker
     * 
     * @param customer Thông tin khách hàng
     * @return Customer đã đăng ký hoặc fallback
     */
    Customer registerCustomer(Customer customer);

    /**
     * Tạo tokens xác thực với circuit breaker
     * 
     * @param userDetails Thông tin người dùng
     * @return Map chứa accessToken và refreshToken
     */
    Map<String, String> generateTokens(UserDetails userDetails);
}