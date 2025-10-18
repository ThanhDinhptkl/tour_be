package com.tour.customerservice.service;

import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Retryable;

import java.sql.SQLException;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

public interface DatabaseService {
    /**
     * Thực thi một thao tác database với cơ chế retry
     * 
     * @param operation Thao tác cần thực hiện
     * @param <T>       Kiểu dữ liệu trả về
     * @return Kết quả từ thao tác
     */
    @Retryable(value = { SQLException.class }, maxAttempts = 3, backoff = @Backoff(delay = 5000, multiplier = 2))
    <T> T executeWithRetry(Supplier<T> operation);

    /**
     * Thực thi một thao tác database không có giá trị trả về với cơ chế retry
     * 
     * @param operation Thao tác cần thực hiện
     */
    @Retryable(value = { SQLException.class }, maxAttempts = 3, backoff = @Backoff(delay = 5000, multiplier = 2))
    void executeWithRetryNoReturn(Runnable operation);
}