package com.tour.paymentservice.services;

import com.tour.paymentservice.dto.PaymentRequestDto;
import com.tour.paymentservice.dto.PaymentResponseDto;

public interface PaymentService {
    PaymentResponseDto createPayment(PaymentRequestDto request);

    PaymentResponseDto getPaymentByOrderId(String orderId);
}