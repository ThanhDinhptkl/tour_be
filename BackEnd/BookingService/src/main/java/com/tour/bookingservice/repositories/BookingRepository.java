package com.tour.bookingservice.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.tour.bookingservice.entities.Booking;

public interface BookingRepository extends JpaRepository<Booking, Integer> {
	

}
