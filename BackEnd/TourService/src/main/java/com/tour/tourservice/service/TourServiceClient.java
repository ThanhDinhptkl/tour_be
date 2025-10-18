package com.tour.tourservice.service;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import com.tour.tourservice.model.Tour;

@FeignClient(name = "tour-service")
public interface TourServiceClient {
    @GetMapping("/tours/{id}")
    Tour getTourById(@PathVariable Long id);
}