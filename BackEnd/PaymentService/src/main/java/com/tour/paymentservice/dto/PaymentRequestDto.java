package com.tour.paymentservice.dto;

import java.math.BigDecimal;

import com.tour.paymentservice.entities.PaymentMethod;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PaymentRequestDto {
    private String orderId;
    private BigDecimal amount;
    private PaymentMethod paymentMethod;
    private String returnUrl;
    private String customerEmail;
    private String description;
}