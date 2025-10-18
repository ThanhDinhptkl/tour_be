package com.tour.paymentservice.services;

import org.springframework.stereotype.Service;

import com.tour.paymentservice.dto.PaymentRequestDto;
import com.tour.paymentservice.dto.PaymentResponseDto;
import com.tour.paymentservice.entities.Payment;
import com.tour.paymentservice.entities.PaymentMethod;
import com.tour.paymentservice.repositories.PaymentRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class PaymentServiceImpl implements PaymentService {

    private final MomoPaymentService momoPaymentService;
    private final VnPayService vnPayService;
    private final PaymentRepository paymentRepository;

    @Override
    public PaymentResponseDto createPayment(PaymentRequestDto request) {
        // Choose the payment gateway based on payment method
        if (request.getPaymentMethod() == PaymentMethod.MOMO) {
            return momoPaymentService.createMomoPayment(request);
        } else if (request.getPaymentMethod() == PaymentMethod.VNPAY) {
            return vnPayService.createVnPayPayment(request);
        }

        throw new IllegalArgumentException("Unsupported payment method: " + request.getPaymentMethod());
    }

    @Override
    public PaymentResponseDto getPaymentByOrderId(String orderId) {
        Payment payment = paymentRepository.findByOrderId(orderId);
        if (payment == null) {
            return null;
        }

        PaymentResponseDto responseDto = PaymentResponseDto.builder()
                .orderId(payment.getOrderId())
                .transactionId(payment.getTransactionId())
                .amount(payment.getAmount())
                .paymentMethod(payment.getPaymentMethod())
                .status(payment.getStatus())
                .paymentUrl(payment.getPaymentUrl())
                .responseCode(payment.getResponseCode())
                .responseMessage(payment.getResponseMessage())
                .build();

        return responseDto;
    }
}