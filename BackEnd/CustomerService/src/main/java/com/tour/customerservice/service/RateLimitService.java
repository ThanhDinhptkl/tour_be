package com.tour.customerservice.service;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RateLimitService {

    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    @Value("${rate.limit.capacity:1000}")
    private int capacity;

    @Value("${rate.limit.refill-tokens:1000}")
    private int refillTokens;

    @Value("${rate.limit.refill-duration:3600}")
    private int refillDurationInSeconds;

    /**
     * Lấy hoặc tạo mới bucket cho một client
     * 
     * @param key Khóa định danh client (IP hoặc API key)
     * @return Bucket tương ứng
     */
    public Bucket resolveBucket(String key) {
        return buckets.computeIfAbsent(key, this::createNewBucket);
    }

    /**
     * Tạo mới một bucket với giới hạn rate limit từ cấu hình
     * 
     * @param key Khóa định danh client
     * @return Bucket mới
     */
    private Bucket createNewBucket(String key) {
        Refill refill = Refill.greedy(refillTokens, Duration.ofSeconds(refillDurationInSeconds));
        Bandwidth limit = Bandwidth.classic(capacity, refill);
        return Bucket.builder().addLimit(limit).build();
    }
}