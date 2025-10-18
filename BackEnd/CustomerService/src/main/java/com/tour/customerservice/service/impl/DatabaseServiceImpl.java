package com.tour.customerservice.service.impl;

import com.tour.customerservice.service.DatabaseService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.retry.annotation.Recover;
import org.springframework.stereotype.Service;

import java.sql.SQLException;
import java.util.function.Supplier;

@Service
public class DatabaseServiceImpl implements DatabaseService {
    private static final Logger logger = LoggerFactory.getLogger(DatabaseServiceImpl.class);

    @Override
    public <T> T executeWithRetry(Supplier<T> operation) {
        try {
            logger.info("Đang thực hiện thao tác database...");
            return operation.get();
        } catch (Exception e) {
            logger.error("Lỗi khi thực hiện thao tác database: {}", e.getMessage());
            if (e.getCause() instanceof SQLException) {
                throw new RuntimeException(e.getCause());
            }
            throw e;
        }
    }

    @Override
    public void executeWithRetryNoReturn(Runnable operation) {
        try {
            logger.info("Đang thực hiện thao tác database không có giá trị trả về...");
            operation.run();
        } catch (Exception e) {
            logger.error("Lỗi khi thực hiện thao tác database: {}", e.getMessage());
            if (e.getCause() instanceof SQLException) {
                throw new RuntimeException(e.getCause());
            }
            throw e;
        }
    }

    @Recover
    public <T> T recoverFromDatabaseError(SQLException e, Supplier<T> operation) {
        logger.error("Đã thử lại thao tác database nhiều lần nhưng không thành công: {}", e.getMessage());
        throw new RuntimeException("Không thể kết nối tới database sau nhiều lần thử lại", e);
    }

    @Recover
    public void recoverFromDatabaseErrorNoReturn(SQLException e, Runnable operation) {
        logger.error("Đã thử lại thao tác database không có giá trị trả về nhiều lần nhưng không thành công: {}",
                e.getMessage());
        throw new RuntimeException("Không thể kết nối tới database sau nhiều lần thử lại", e);
    }
}