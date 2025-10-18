package com.tour.customerservice.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tour.customerservice.service.RateLimitService;
import io.github.bucket4j.Bucket;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(RateLimitFilter.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    private RateLimitService rateLimitService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Lấy địa chỉ IP của client
        String clientIp = getClientIP(request);
        logger.debug("Incoming request from IP: {}", clientIp);

        // Lấy bucket tương ứng cho client
        Bucket bucket = rateLimitService.resolveBucket(clientIp);

        // Kiểm tra xem còn token không
        if (bucket.tryConsume(1)) {
            // Còn token, cho phép request đi qua
            filterChain.doFilter(request, response);
        } else {
            // Hết token, từ chối request với status 429 (Too Many Requests)
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);

            Map<String, Object> errorDetails = new HashMap<>();
            errorDetails.put("status", HttpStatus.TOO_MANY_REQUESTS.value());
            errorDetails.put("error", "Rate limit exceeded");
            errorDetails.put("message", "Quá nhiều yêu cầu, vui lòng thử lại sau");

            response.getWriter().write(objectMapper.writeValueAsString(errorDetails));
            logger.warn("Rate limit exceeded for IP: {}", clientIp);
        }
    }

    private String getClientIP(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            // Lấy địa chỉ IP đầu tiên trong chuỗi X-Forwarded-For
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}