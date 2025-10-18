package com.tour.paymentservice.controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.tour.paymentservice.dto.PaymentRequestDto;
import com.tour.paymentservice.dto.PaymentResponseDto;
import com.tour.paymentservice.services.PaymentService;
import com.tour.paymentservice.services.VnPayService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;

@RestController
@RequestMapping("/api/payments")
@RequiredArgsConstructor
@Slf4j
public class PaymentController {

    private final PaymentService paymentService;
    private final VnPayService vnPayService;

    @PostMapping
    public ResponseEntity<PaymentResponseDto> createPayment(@RequestBody PaymentRequestDto requestDto) {
        log.info("Creating payment with method: {}", requestDto.getPaymentMethod());

        PaymentResponseDto response = paymentService.createPayment(requestDto);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/{orderId}")
    public ResponseEntity<PaymentResponseDto> getPaymentStatus(@PathVariable String orderId) {
        log.info("Getting payment status for order: {}", orderId);

        PaymentResponseDto response = paymentService.getPaymentByOrderId(orderId);
        if (response == null) {
            return ResponseEntity.notFound().build();
        }

        return ResponseEntity.ok(response);
    }

    @GetMapping("/vnpay/callback")
    public ResponseEntity<String> processVnPayCallback(@RequestParam Map<String, String> callbackParams) {
        log.info("VNPay callback received: {}", callbackParams);

        String vnp_ResponseCode = callbackParams.get("vnp_ResponseCode");

        if (vnp_ResponseCode == null) {
            return ResponseEntity.badRequest().body("Missing response code");
        }

        PaymentResponseDto response = vnPayService.processVnPayCallback(callbackParams);

        if (response == null) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to process payment");
        }

        if ("00".equals(vnp_ResponseCode)) {
            return ResponseEntity.ok("Payment processed successfully");
        } else {
            return ResponseEntity.ok("Payment processing failed");
        }
    }
}