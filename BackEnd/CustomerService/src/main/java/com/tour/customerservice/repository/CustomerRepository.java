package com.tour.customerservice.repository;

import com.tour.customerservice.model.Customer;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CustomerRepository extends JpaRepository<Customer, Integer> {
    Optional<Customer> findByEmail(String email); // Tìm kiếm người dùng theo email
    List<Customer> findByPhone(String phone); // Tìm kiếm người dùng theo số điện thoại
}
