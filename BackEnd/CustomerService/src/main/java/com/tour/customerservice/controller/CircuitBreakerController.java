package com.tour.customerservice.controller;

import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@CrossOrigin(origins = "*")
@RequestMapping("/api/circuit-breaker")
public class CircuitBreakerController {

    @Autowired
    private CircuitBreakerRegistry circuitBreakerRegistry;

    @GetMapping("/status/{name}")
    public ResponseEntity<Map<String, Object>> getCircuitBreakerStatus(@PathVariable String name) {
        CircuitBreaker breaker = circuitBreakerRegistry.circuitBreaker(name);
        Map<String, Object> status = new HashMap<>();

        status.put("name", name);
        status.put("state", breaker.getState());
        status.put("metrics", Map.of(
                "failureRate", breaker.getMetrics().getFailureRate(),
                "numberOfFailedCalls", breaker.getMetrics().getNumberOfFailedCalls(),
                "numberOfSuccessfulCalls", breaker.getMetrics().getNumberOfSuccessfulCalls(),
                "numberOfNotPermittedCalls", breaker.getMetrics().getNumberOfNotPermittedCalls()));

        return ResponseEntity.ok(status);
    }

    @GetMapping("/reset/{name}")
    public ResponseEntity<Map<String, String>> resetCircuitBreaker(@PathVariable String name) {
        CircuitBreaker circuitBreaker = circuitBreakerRegistry.circuitBreaker(name);
        circuitBreaker.reset();

        return ResponseEntity.ok(Map.of("status", "Circuit breaker '" + name + "' đã được reset."));
    }

    @GetMapping("/force-open/{name}")
    public ResponseEntity<Map<String, String>> forceOpenCircuitBreaker(@PathVariable String name) {
        CircuitBreaker circuitBreaker = circuitBreakerRegistry.circuitBreaker(name);
        circuitBreaker.transitionToForcedOpenState();

        return ResponseEntity
                .ok(Map.of("status", "Circuit breaker '" + name + "' đã chuyển trạng thái sang FORCED_OPEN."));
    }

    @GetMapping("/force-close/{name}")
    public ResponseEntity<Map<String, String>> forceCloseCircuitBreaker(@PathVariable String name) {
        CircuitBreaker circuitBreaker = circuitBreakerRegistry.circuitBreaker(name);
        circuitBreaker.transitionToClosedState();

        return ResponseEntity.ok(Map.of("status", "Circuit breaker '" + name + "' đã chuyển trạng thái sang CLOSED."));
    }
}