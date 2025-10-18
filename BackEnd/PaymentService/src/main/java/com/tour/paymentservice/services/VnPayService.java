package com.tour.paymentservice.services;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;
import java.util.UUID;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

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
public class VnPayService {

    private final PaymentConfig paymentConfig;
    private final PaymentRepository paymentRepository;
    private final ModelMapper modelMapper;

    public PaymentResponseDto createVnPayPayment(PaymentRequestDto requestDto) {
        try {
            String transactionId = UUID.randomUUID().toString();

            // Get vnp_PayDate
            Calendar cld = Calendar.getInstance(TimeZone.getTimeZone("Etc/GMT+7"));
            SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
            String vnp_CreateDate = formatter.format(cld.getTime());

            // Add parameters
            Map<String, String> vnp_Params = new HashMap<>();
            vnp_Params.put("vnp_Version", "2.1.0");
            vnp_Params.put("vnp_Command", "pay");
            vnp_Params.put("vnp_TmnCode", paymentConfig.getVnpayTmnCode());
            vnp_Params.put("vnp_Amount", String.valueOf(requestDto.getAmount().intValue() * 100));
            vnp_Params.put("vnp_CurrCode", "VND");
            vnp_Params.put("vnp_BankCode", "");
            vnp_Params.put("vnp_TxnRef", requestDto.getOrderId());
            vnp_Params.put("vnp_OrderInfo", requestDto.getDescription());
            vnp_Params.put("vnp_OrderType", "other");
            vnp_Params.put("vnp_Locale", "vn");
            vnp_Params.put("vnp_ReturnUrl", requestDto.getReturnUrl());
            vnp_Params.put("vnp_IpAddr", "127.0.0.1");
            vnp_Params.put("vnp_CreateDate", vnp_CreateDate);

            // Build data to hash and query string
            List<String> fieldNames = new ArrayList<>(vnp_Params.keySet());
            Collections.sort(fieldNames);

            StringBuilder hashData = new StringBuilder();
            StringBuilder query = new StringBuilder();

            Iterator<String> itr = fieldNames.iterator();
            while (itr.hasNext()) {
                String fieldName = itr.next();
                String fieldValue = vnp_Params.get(fieldName);
                if ((fieldValue != null) && (fieldValue.length() > 0)) {
                    // Build hash data
                    hashData.append(fieldName);
                    hashData.append('=');
                    hashData.append(URLEncoder.encode(fieldValue, StandardCharsets.US_ASCII.toString()));

                    // Build query
                    query.append(URLEncoder.encode(fieldName, StandardCharsets.US_ASCII.toString()));
                    query.append('=');
                    query.append(URLEncoder.encode(fieldValue, StandardCharsets.US_ASCII.toString()));

                    if (itr.hasNext()) {
                        query.append('&');
                        hashData.append('&');
                    }
                }
            }

            String queryUrl = query.toString();

            // Create HMAC-SHA512 signature
            String vnp_SecureHash = hmacSHA512(paymentConfig.getVnpayHashSecret(), hashData.toString());
            queryUrl += "&vnp_SecureHash=" + vnp_SecureHash;

            String paymentUrl = paymentConfig.getVnpayEndpoint() + "?" + queryUrl;

            // Save payment to database
            Payment payment = Payment.builder()
                    .orderId(requestDto.getOrderId())
                    .transactionId(transactionId)
                    .amount(requestDto.getAmount())
                    .paymentMethod(PaymentMethod.VNPAY)
                    .status(PaymentStatus.PENDING)
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .paymentUrl(paymentUrl)
                    .customerEmail(requestDto.getCustomerEmail())
                    .description(requestDto.getDescription())
                    .build();

            paymentRepository.save(payment);

            // Map to response DTO
            PaymentResponseDto responseDto = modelMapper.map(payment, PaymentResponseDto.class);
            return responseDto;

        } catch (Exception e) {
            log.error("Error creating VNPay payment: {}", e.getMessage());

            // Create failed payment record
            Payment payment = Payment.builder()
                    .orderId(requestDto.getOrderId())
                    .transactionId(UUID.randomUUID().toString())
                    .amount(requestDto.getAmount())
                    .paymentMethod(PaymentMethod.VNPAY)
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

    public PaymentResponseDto processVnPayCallback(Map<String, String> callbackParams) {
        try {
            String vnp_ResponseCode = callbackParams.get("vnp_ResponseCode");
            String vnp_TxnRef = callbackParams.get("vnp_TxnRef");
            String vnp_TransactionNo = callbackParams.get("vnp_TransactionNo");

            log.info("Processing VNPay callback for order {}, response code: {}", vnp_TxnRef, vnp_ResponseCode);

            // Find the payment by orderId
            Payment payment = paymentRepository.findByOrderId(vnp_TxnRef);

            if (payment != null) {
                // Update payment status
                if ("00".equals(vnp_ResponseCode)) {
                    payment.setStatus(PaymentStatus.COMPLETED);
                } else {
                    payment.setStatus(PaymentStatus.FAILED);
                }

                payment.setResponseCode(vnp_ResponseCode);
                payment.setResponseMessage("Transaction " + ("00".equals(vnp_ResponseCode) ? "successful" : "failed"));
                payment.setUpdatedAt(LocalDateTime.now());

                if (vnp_TransactionNo != null) {
                    payment.setTransactionId(vnp_TransactionNo);
                }

                paymentRepository.save(payment);

                // Map to response DTO
                PaymentResponseDto responseDto = modelMapper.map(payment, PaymentResponseDto.class);
                return responseDto;
            }

            log.error("Payment not found for order: {}", vnp_TxnRef);
            return null;
        } catch (Exception e) {
            log.error("Error processing VNPay callback: {}", e.getMessage());
            return null;
        }
    }

    private String hmacSHA512(String key, String data) {
        try {
            Mac sha512_HMAC = Mac.getInstance("HmacSHA512");
            SecretKeySpec secret_key = new SecretKeySpec(key.getBytes(), "HmacSHA512");
            sha512_HMAC.init(secret_key);
            byte[] hash = sha512_HMAC.doFinal(data.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            log.error("Error creating HMAC-SHA512: {}", e.getMessage());
            return "";
        }
    }
}