package com.tour.customerservice.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.retry.annotation.EnableRetry;

@Configuration
@EnableRetry
public class RetryConfig {
    // Cấu hình retry mặc định được định nghĩa qua annotations
}