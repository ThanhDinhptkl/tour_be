package com.tour.paymentservice.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.tour.paymentservice.dto.PaymentResponseDto;
import com.tour.paymentservice.entities.PaymentStatus;
import com.tour.paymentservice.services.PaymentService;
import com.tour.paymentservice.services.VnPayService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@Slf4j
public class PaymentResultController {

    private final PaymentService paymentService;
    private final VnPayService vnPayService;

    @GetMapping("/payment-result")
    public ResponseEntity<String> paymentResult(
            @RequestParam(required = false) String vnp_ResponseCode,
            @RequestParam(required = false) String vnp_TxnRef,
            @RequestParam(required = false) String vnp_Amount,
            @RequestParam(required = false) String vnp_OrderInfo,
            @RequestParam(required = false) String vnp_TransactionNo,
            @RequestParam Map<String, String> allParams) {

        log.info("Payment result received: {}", allParams);

        // Procesar el pago y actualizar su estado
        if (vnp_TxnRef != null && vnp_ResponseCode != null) {
            vnPayService.processVnPayCallback(allParams);
        }

        String resultPage = "<html><head><meta charset='UTF-8'><body style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;'>";
        resultPage += "<h1 style='color: #2c3e50;'>Kết quả thanh toán</h1>";

        if ("00".equals(vnp_ResponseCode)) {
            // Kiểm tra lại payment trong DB
            PaymentResponseDto payment = paymentService.getPaymentByOrderId(vnp_TxnRef);

            resultPage += "<div style='background-color: #d4edda; border-color: #c3e6cb; color: #155724; padding: 15px; border-radius: 4px; margin-bottom: 20px;'>";
            resultPage += "<h2 style='margin-top: 0;'>Thanh toán thành công!</h2>";
            resultPage += "</div>";

            resultPage += "<div style='background-color: #f8f9fa; padding: 15px; border-radius: 4px;'>";
            resultPage += "<p><strong>Mã đơn hàng:</strong> " + vnp_TxnRef + "</p>";
            resultPage += "<p><strong>Số tiền:</strong> " + (vnp_Amount != null ? formatAmount(vnp_Amount) : "0")
                    + " VND</p>";
            resultPage += "<p><strong>Nội dung:</strong> " + vnp_OrderInfo + "</p>";
            resultPage += "<p><strong>Mã giao dịch VNPay:</strong> " + vnp_TransactionNo + "</p>";
            resultPage += "</div>";

            resultPage += "<p style='margin-top: 20px;'><a href='/' style='background-color: #007bff; color: white; padding: 10px 15px; text-decoration: none; border-radius: 4px;'>Quay lại trang chủ</a></p>";
        } else {
            resultPage += "<div style='background-color: #f8d7da; border-color: #f5c6cb; color: #721c24; padding: 15px; border-radius: 4px; margin-bottom: 20px;'>";
            resultPage += "<h2 style='margin-top: 0;'>Thanh toán thất bại!</h2>";
            resultPage += "<p>Mã lỗi: " + vnp_ResponseCode + "</p>";
            resultPage += "</div>";

            resultPage += "<p style='margin-top: 20px;'><a href='/' style='background-color: #dc3545; color: white; padding: 10px 15px; text-decoration: none; border-radius: 4px;'>Thử lại</a></p>";
        }

        resultPage += "</body></html>";

        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("text/html; charset=UTF-8"))
                .body(resultPage);
    }

    private String formatAmount(String amount) {
        try {
            long amountValue = Long.parseLong(amount);
            // VNPay trả về số tiền đã nhân 100
            amountValue = amountValue / 100;
            return String.format("%,d", amountValue);
        } catch (NumberFormatException e) {
            return amount;
        }
    }
}