package org.microservice.api_gateway.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    private static final Logger LOGGER = Logger.getLogger(AuthenticationFilter.class.getName());
    private final String secret = "pR8dXJZtG6qM9wKf3uYvL2sBzT4cV1oX5nA7mN0QWgE";
    private SecretKey secretKey;

    @PostConstruct
    public void init() {
        byte[] keyBytes = Base64.getDecoder().decode(secret);
        this.secretKey = Keys.hmacShaKeyFor(keyBytes);
    }

    public AuthenticationFilter() {
        super(Config.class);
    }

    public static class Config {
        // Cấu hình nếu cần
    }

    private static final Set<String> PUBLIC_ENDPOINTS = Set.of(
            "GET:/tour", // GET tất cả tour
            "GET:/tours", // GET danh sách tour
            "GET:/tours/.*", // GET danh sách tour sau khi lọc
            "GET:/tour/\\d+", // GET chi tiết tour
            "POST:/customer/auth/.*",
            "GET:/customer/auth/.*",
            "/oauth2/.*");

    private static final Map<String, Set<String>> ROUTE_ROLES = Map.of(
            "POST:/tour", Set.of("ROLE_ADMIN"),
            "POST:/tours", Set.of("ROLE_ADMIN"),
            "PUT:/tour", Set.of("ROLE_ADMIN"),
            "DELETE:/tour/delete/\\d+", Set.of("ROLE_ADMIN"),

            // CUSTOMER và ADMIN có thể đặt, update booking
            "POST:/booking", Set.of("ROLE_CUSTOMER", "ROLE_ADMIN"),
            "PUT:/booking", Set.of("ROLE_CUSTOMER", "ROLE_ADMIN"),

            // CUSTOMER, ADMIN có thể xem lịch sử booking của mình
            "GET:/booking/\\d+", Set.of("ROLE_CUSTOMER", "ROLE_ADMIN"),

            // ADMIN có thể xem tất cả booking
            "GET:/bookings", Set.of("ROLE_ADMIN"),

            // CUSTOMER, ADMIN có thể hủy booking của mình
            "DELETE:/booking/\\d+", Set.of("ROLE_CUSTOMER", "ROLE_ADMIN"));

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String path = exchange.getRequest().getURI().getPath();
            String method = exchange.getRequest().getMethod().toString();
            LOGGER.info("🔍 Request: " + method + " " + path);

            // Nếu là public endpoint, bỏ qua xác thực
            if (isPublicEndpoint(path, method)) {
                LOGGER.info("✅ Bỏ qua xác thực cho: " + method + " " + path);
                return chain.filter(exchange);
            }

            // Kiểm tra Authorization header
            String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return onError(exchange, "❌ Missing or invalid Authorization header", HttpStatus.UNAUTHORIZED);
            }

            // Giải mã token JWT
            String token = authHeader.substring(7);
            Claims claims;
            try {
                LOGGER.info("🔑 Token: " + token);
                claims = Jwts.parserBuilder()
                        .setSigningKey(secretKey)
                        .build()
                        .parseClaimsJws(token)
                        .getBody();
            } catch (Exception e) {
                LOGGER.warning("❌ Lỗi giải mã token: " + e.getMessage());
                return onError(exchange, "❌ Invalid JWT Token", HttpStatus.UNAUTHORIZED);
            }

            // Lấy role từ JWT
            String userRole = claims.get("role", String.class);
            LOGGER.info("🔑 Role của user: " + userRole);

            // Kiểm tra quyền truy cập
            boolean isAuthorized = ROUTE_ROLES.entrySet().stream()
                    .filter(entry -> (method + ":" + path).matches(entry.getKey()))
                    .peek(entry -> LOGGER.info("📌 Role cần thiết: " + entry.getValue()))
                    .anyMatch(entry -> entry.getValue().contains(userRole));

            if (!isAuthorized) {
                return onError(exchange, "⛔ Access Denied", HttpStatus.FORBIDDEN);
            }

            return chain.filter(exchange);
        };
    }

    private boolean isPublicEndpoint(String path, String method) {
        return PUBLIC_ENDPOINTS.stream().anyMatch(endpoint -> {
            if (endpoint.contains(":")) {
                String[] parts = endpoint.split(":");
                return parts[0].equalsIgnoreCase(method) && path.matches(parts[1]);
            }
            return path.matches(endpoint);
        });
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus status) {
        LOGGER.warning(err);
        exchange.getResponse().setStatusCode(status);
        return exchange.getResponse().setComplete();
    }
}
