package com.tour.tourservice.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.tour.tourservice.model.Tour;

public interface TourRepository extends JpaRepository<Tour, Integer>{

	List<Tour> findByLocation(String location);

	List<Tour> findByTitle(String title);
	
	@Query("SELECT t FROM Tour t WHERE t.price BETWEEN :minPrice AND :maxPrice ORDER BY t.price ASC")
    List<Tour> findByPriceBetween(@Param("minPrice") double minPrice, @Param("maxPrice") double maxPrice);
}
