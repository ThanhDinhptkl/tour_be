package com.tour.bookingservice.service;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import com.tour.bookingservice.dto.TourDTO;


@FeignClient(name = "TourService")
public interface TourServiceClient {
    @GetMapping("/tour/{id}")
    TourDTO getTourById(@PathVariable int id);
}