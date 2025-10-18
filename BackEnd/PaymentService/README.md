# Payment Microservice

This microservice handles payment processing with Momo and VNPay payment gateways.

## Features

- Process payments with Momo
- Process payments with VNPay
- Payment status tracking
- Callback handling for payment confirmation

## API Endpoints

### Create Payment

```
POST /api/payments
```

Request body:
```json
{
  "orderId": "ORDER123",
  "amount": 100000,
  "paymentMethod": "MOMO",
  "returnUrl": "http://yourdomain.com/return",
  "customerEmail": "customer@example.com",
  "description": "Payment for order ORDER123"
}
```

Response:
```json
{
  "orderId": "ORDER123",
  "transactionId": "some-uuid",
  "amount": 100000,
  "paymentMethod": "MOMO",
  "status": "PENDING",
  "paymentUrl": "https://payment-gateway-url",
  "responseCode": "0",
  "responseMessage": "Success"
}
```

### Get Payment Status

```
GET /api/payments/{orderId}
```

Response:
```json
{
  "orderId": "ORDER123",
  "transactionId": "some-uuid",
  "amount": 100000,
  "paymentMethod": "MOMO",
  "status": "COMPLETED",
  "paymentUrl": "https://payment-gateway-url",
  "responseCode": "0",
  "responseMessage": "Success"
}
```

## Configuration

Configuration is done through `application.properties`:

```properties
# Momo configuration
momo.endpoint=https://test-payment.momo.vn/v2/gateway/api/create
momo.partner-code=your-partner-code
momo.access-key=your-access-key
momo.secret-key=your-secret-key
momo.callback-url=http://yourdomain.com/api/payments/momo/callback

# VNPay configuration
vnpay.endpoint=https://sandbox.vnpayment.vn/paymentv2/vpcpay.html
vnpay.tmncode=your-tmn-code
vnpay.hashsecret=your-hash-secret
vnpay.callback-url=http://yourdomain.com/api/payments/vnpay/callback
```

## Running with Docker

This service is designed to work with Docker and can be started using:

```bash
docker-compose up payment-service
``` 