package com.tour.bookingservice.service;

import java.util.ArrayList;
import java.util.List;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


import com.tour.bookingservice.dto.BookingServiceDTO;
import com.tour.bookingservice.dto.TourDTO;
import com.tour.bookingservice.entities.Booking;
import com.tour.bookingservice.repositories.BookingRepository;

public interface BookingService {
	void add(BookingServiceDTO bookingservicedto);
	void update(BookingServiceDTO bookingservicedto);
	void delete(Integer id);
	List<BookingServiceDTO> getAll();
	BookingServiceDTO getOne(Integer id);
	 TourDTO getTourDetails(int tourId);
	
}



