package com.tour.tourservice.config;

import com.cloudinary.Cloudinary;
import com.cloudinary.utils.ObjectUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class CloudinaryConfig {

    @Bean
    public Cloudinary cloudinary() {
        Map<String, String> config = new HashMap<>();
        config.put("cloud_name", "dj7l7khdy");
        config.put("api_key", "321578145121169");
        config.put("api_secret", "c4U8MUebfkPd6_FLocp2YwRWRGU");
        return new Cloudinary(config);
    }
} 