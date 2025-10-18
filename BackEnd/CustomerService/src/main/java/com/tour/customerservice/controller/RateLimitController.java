package com.tour.customerservice.controller;

import com.tour.customerservice.service.RateLimitService;
import io.github.bucket4j.Bucket;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@CrossOrigin(origins = "*")
@RequestMapping("/api/rate-limit")
public class RateLimitController {

    @Autowired
    private RateLimitService rateLimitService;

    /**
     * Endpoint để kiểm tra trạng thái rate limit hiện tại của client
     * 
     * @param request HTTP request
     * @return Thông tin về trạng thái rate limit
     */
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getRateLimitStatus(HttpServletRequest request) {
        String clientIp = getClientIP(request);
        Bucket bucket = rateLimitService.resolveBucket(clientIp);

        Map<String, Object> status = new HashMap<>();
        status.put("availableTokens", bucket.getAvailableTokens());
        status.put("clientIp", clientIp);

        return ResponseEntity.ok(status);
    }

    private String getClientIP(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}