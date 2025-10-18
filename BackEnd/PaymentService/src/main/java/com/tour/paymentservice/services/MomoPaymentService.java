package com.tour.paymentservice.services;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tour.paymentservice.config.PaymentConfig;
import com.tour.paymentservice.dto.PaymentRequestDto;
import com.tour.paymentservice.dto.PaymentResponseDto;
import com.tour.paymentservice.entities.Payment;
import com.tour.paymentservice.entities.PaymentMethod;
import com.tour.paymentservice.entities.PaymentStatus;
import com.tour.paymentservice.repositories.PaymentRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class MomoPaymentService {

    private final PaymentConfig paymentConfig;
    private final WebClient webClient;
    private final PaymentRepository paymentRepository;
    private final ModelMapper modelMapper;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public PaymentResponseDto createMomoPayment(PaymentRequestDto requestDto) {
        try {
            String transactionId = UUID.randomUUID().toString();

            // Prepare request body for Momo API
            Map<String, Object> requestBody = new HashMap<>();
            requestBody.put("partnerCode", paymentConfig.getMomoPartnerCode());
            requestBody.put("accessKey", paymentConfig.getMomoAccessKey());
            requestBody.put("requestId", transactionId);
            requestBody.put("amount", requestDto.getAmount().doubleValue());
            requestBody.put("orderId", requestDto.getOrderId());
            requestBody.put("orderInfo", requestDto.getDescription());
            requestBody.put("returnUrl", requestDto.getReturnUrl());
            requestBody.put("notifyUrl", paymentConfig.getMomoCallbackUrl());
            requestBody.put("requestType", "captureMoMoWallet");
            requestBody.put("extraData", "");

            // Generate signature
            String rawSignature = "partnerCode=" + paymentConfig.getMomoPartnerCode() +
                    "&accessKey=" + paymentConfig.getMomoAccessKey() +
                    "&requestId=" + transactionId +
                    "&amount=" + requestDto.getAmount().doubleValue() +
                    "&orderId=" + requestDto.getOrderId() +
                    "&orderInfo=" + requestDto.getDescription() +
                    "&returnUrl=" + requestDto.getReturnUrl() +
                    "&notifyUrl=" + paymentConfig.getMomoCallbackUrl() +
                    "&extraData=";

            String signature = new HmacUtils(HmacAlgorithms.HMAC_SHA_256,
                    paymentConfig.getMomoSecretKey()).hmacHex(rawSignature);

            requestBody.put("signature", signature);

            // Call Momo API
            String responseBody = webClient.post()
                    .uri(paymentConfig.getMomoEndpoint())
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                    .body(BodyInserters.fromValue(requestBody))
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

            // Parse response
            Map<String, Object> responseMap = objectMapper.readValue(responseBody, Map.class);

            // Save payment to database
            Payment payment = Payment.builder()
                    .orderId(requestDto.getOrderId())
                    .transactionId(transactionId)
                    .amount(requestDto.getAmount())
                    .paymentMethod(PaymentMethod.MOMO)
                    .status(PaymentStatus.PENDING)
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .paymentUrl((String) responseMap.get("payUrl"))
                    .responseCode((String) responseMap.get("resultCode"))
                    .responseMessage((String) responseMap.get("message"))
                    .customerEmail(requestDto.getCustomerEmail())
                    .description(requestDto.getDescription())
                    .build();

            paymentRepository.save(payment);

            // Map to response DTO
            PaymentResponseDto responseDto = modelMapper.map(payment, PaymentResponseDto.class);
            return responseDto;

        } catch (Exception e) {
            log.error("Error creating Momo payment: {}", e.getMessage());

            // Create failed payment record
            Payment payment = Payment.builder()
                    .orderId(requestDto.getOrderId())
                    .transactionId(UUID.randomUUID().toString())
                    .amount(requestDto.getAmount())
                    .paymentMethod(PaymentMethod.MOMO)
                    .status(PaymentStatus.FAILED)
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .responseCode("ERROR")
                    .responseMessage(e.getMessage())
                    .customerEmail(requestDto.getCustomerEmail())
                    .description(requestDto.getDescription())
                    .build();

            paymentRepository.save(payment);

            // Map to response DTO
            PaymentResponseDto responseDto = modelMapper.map(payment, PaymentResponseDto.class);
            return responseDto;
        }
    }

    public PaymentResponseDto processMomoCallback(String requestData) {
        try {
            Map<String, Object> callbackData = objectMapper.readValue(requestData, Map.class);

            String orderId = (String) callbackData.get("orderId");
            String resultCode = (String) callbackData.get("resultCode");

            // Find the payment by orderId
            Payment payment = paymentRepository.findByOrderId(orderId);

            if (payment != null) {
                // Update payment status
                if ("0".equals(resultCode)) {
                    payment.setStatus(PaymentStatus.COMPLETED);
                } else {
                    payment.setStatus(PaymentStatus.FAILED);
                }

                payment.setResponseCode(resultCode);
                payment.setResponseMessage((String) callbackData.get("message"));
                payment.setUpdatedAt(LocalDateTime.now());

                paymentRepository.save(payment);

                // Map to response DTO
                PaymentResponseDto responseDto = modelMapper.map(payment, PaymentResponseDto.class);
                return responseDto;
            }

            return null;
        } catch (JsonProcessingException e) {
            log.error("Error processing Momo callback: {}", e.getMessage());
            return null;
        }
    }

    public String createQrCodePayment(PaymentRequestDto requestDto) {
        String storeSlug = paymentConfig.getMomoPartnerCode() + "-storeid01"; // Thay đổi theo cấu hình
        long amount = requestDto.getAmount().longValue();
        String billId = requestDto.getOrderId();

        // Tạo chữ ký
        String rawSignature = "storeSlug=" + storeSlug +
                "&amount=" + amount +
                "&billId=" + billId;
        String signature = new HmacUtils(HmacAlgorithms.HMAC_SHA_256,
                paymentConfig.getMomoSecretKey()).hmacHex(rawSignature);

        // Tạo URI cho QR code
        String qrCodeUrl = "https://test-payment.momo.vn/pay/store/" + storeSlug +
                "?a=" + amount +
                "&b=" + billId +
                "&s=" + signature;

        // Lưu thông tin thanh toán với QR
        Payment payment = Payment.builder()
                .orderId(requestDto.getOrderId())
                .transactionId(UUID.randomUUID().toString())
                .amount(requestDto.getAmount())
                .paymentMethod(PaymentMethod.MOMO)
                .status(PaymentStatus.PENDING)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .paymentUrl(qrCodeUrl)
                .customerEmail(requestDto.getCustomerEmail())
                .description(requestDto.getDescription())
                .build();

        paymentRepository.save(payment);

        return qrCodeUrl;
    }
}