package com.tour.bookingservice.service.impl;

import java.util.ArrayList;
import java.util.List;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.tour.bookingservice.dto.BookingServiceDTO;
import com.tour.bookingservice.dto.TourDTO;
import com.tour.bookingservice.entities.Booking;
import com.tour.bookingservice.repositories.BookingRepository;
import com.tour.bookingservice.service.BookingService;
import com.tour.bookingservice.service.TourServiceClient;

@Service
class BookingServiceImpl implements BookingService{
	@Autowired
	BookingRepository bookingrepository;	

	@Autowired
	ModelMapper modelMapper;
	
	 @Autowired
	 private TourServiceClient tourServiceClient;
	 
	    @Autowired
	    public BookingServiceImpl(TourServiceClient tourServiceClient) {
	        this.tourServiceClient = tourServiceClient;
	    }

	    public TourDTO getTourDetails(int tourId) {
	        return tourServiceClient.getTourById(tourId);
	    }

	@Override
	public void add(BookingServiceDTO bookingservicedto) {
		// TODO Auto-generated method stub
		Booking booking = modelMapper.map(bookingservicedto, Booking.class);

		bookingrepository.save(booking);

		bookingservicedto.setId(booking.getId());
	}
	@Override
	public void update(BookingServiceDTO bookingservicedto) {
		// TODO Auto-generated method stub
		Booking booking = bookingrepository.getById(bookingservicedto.getId());
		if (booking != null) {
			modelMapper.map(bookingservicedto, booking);
			bookingrepository.save(booking);
		}
	}

	@Override
	public void delete(Integer id) {
		// TODO Auto-generated method stub
		Booking booking = bookingrepository.getById(id);
		if (booking != null) {
			bookingrepository.delete(booking);
		}

	}

	@Override
	public List<BookingServiceDTO> getAll() {
		// TODO Auto-generated method stub
		List<BookingServiceDTO> bookingServiceDTOs = new ArrayList<>();

		bookingrepository.findAll().forEach((booking) -> {
			bookingServiceDTOs.add(modelMapper.map(booking, BookingServiceDTO.class));
		});
		return bookingServiceDTOs;
	}
	@Override
	public BookingServiceDTO getOne(Integer id) {
		// TODO Auto-generated method stub
		Booking booking = bookingrepository.getById(id);
		if (booking != null) {
            return modelMapper.map(booking, BookingServiceDTO.class);
		}
		return null;
	}

}