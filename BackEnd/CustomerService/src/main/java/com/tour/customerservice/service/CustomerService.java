package com.tour.customerservice.service;

import com.tour.customerservice.model.Customer;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.List;
import java.util.Map;

public interface CustomerService extends UserDetailsService {
    Customer registerCustomer(Customer customer); // Đăng ký người dùng mới
    Customer findByEmail(String email); // Tìm kiếm người dùng theo email
    Customer findByPhone(String phone); // Tìm kiếm người dùng theo số điện thoại
    List<Customer> findAllCustomers(); // Lấy tất cả khách hàng
    Customer updateCustomer(String token, Customer customer); // Cập nhật thông tin khách hàng
    void deleteCustomer(Integer id); // Xóa khách hàng
    void resetPassword(Integer id); // Reset mật khẩu về 12345
    void changePassword(String token, String oldPassword, String newPassword); // Đổi mật khẩu
    Customer saveCustomer(Customer customer);
    public Map<String, String> generateTokens(UserDetails userDetails);
}