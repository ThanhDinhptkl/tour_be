package com.tour.customerservice.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Configuration
public class EnvConfig {
    private static final Logger logger = LoggerFactory.getLogger(EnvConfig.class);

    public EnvConfig() {
        loadEnvFile();
    }

    private void loadEnvFile() {
        Path envPath = Paths.get(".env");

        if (Files.exists(envPath)) {
            try (BufferedReader reader = new BufferedReader(new FileReader(envPath.toFile()))) {
                String line;
                logger.info("Loading environment variables from .env file");

                while ((line = reader.readLine()) != null) {
                    line = line.trim();

                    // Bỏ qua comment và dòng trống
                    if (line.isEmpty() || line.startsWith("#")) {
                        continue;
                    }

                    int delimiterPos = line.indexOf('=');
                    if (delimiterPos > 0) {
                        String key = line.substring(0, delimiterPos).trim();
                        String value = line.substring(delimiterPos + 1).trim();

                        // Xóa quotes nếu có
                        if (value.startsWith("\"") && value.endsWith("\"")) {
                            value = value.substring(1, value.length() - 1);
                        }

                        // Chỉ set nếu biến chưa được định nghĩa
                        if (System.getProperty(key) == null && System.getenv(key) == null) {
                            System.setProperty(key, value);
                            logger.debug("Set environment variable: {} = {}", key, value);
                        }
                    }
                }
                logger.info("Environment variables loaded successfully");
            } catch (IOException e) {
                logger.error("Failed to load .env file: {}", e.getMessage());
            }
        } else {
            logger.warn(".env file not found, using default values from application.properties");
        }
    }
}