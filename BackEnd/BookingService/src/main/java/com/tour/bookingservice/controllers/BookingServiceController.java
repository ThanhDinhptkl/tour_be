package com.tour.bookingservice.controllers;

import java.util.List;
import java.util.Optional;
import java.util.Date;
import java.text.SimpleDateFormat;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.tour.bookingservice.dto.BookingServiceDTO;
import com.tour.bookingservice.dto.TourDTO;
import com.tour.bookingservice.service.BookingService;

@RestController
@CrossOrigin(origins = "http://localhost:5173", 
    allowedHeaders = "*",
    methods = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, 
               RequestMethod.DELETE, RequestMethod.OPTIONS},
    allowCredentials = "true")
public class BookingServiceController {
	@Autowired
	BookingService bookingService;
	
	
	
	
	// add new
	@PostMapping("/booking")
	public ResponseEntity<?> addBooking(@RequestBody BookingServiceDTO bookingServiceDTO) {
		try {
			// Set created_at to current time
			bookingServiceDTO.setCreated_at(new Date());
			
			// Convert booking_date from string if needed
			if (bookingServiceDTO.getBooking_date() == null && bookingServiceDTO.getBooking_date().toString() != null) {
				try {
					SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
					Date bookingDate = dateFormat.parse(bookingServiceDTO.getBooking_date().toString());
					bookingServiceDTO.setBooking_date(bookingDate);
				} catch (Exception e) {
					return ResponseEntity.status(HttpStatus.BAD_REQUEST)
						.body("Invalid booking date format. Please use yyyy-MM-dd format");
				}
			}
			
			// Validate required fields
			if (bookingServiceDTO.getUser_id() <= 0) {
				return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body("Invalid user_id");
			}
			
			if (bookingServiceDTO.getTour_id() <= 0) {
				return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body("Invalid tour_id");
			}
			
			if (bookingServiceDTO.getNumber_of_people() <= 0) {
				return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body("Number of people must be greater than 0");
			}
			
			bookingService.add(bookingServiceDTO);
			return ResponseEntity.ok(bookingServiceDTO);
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
				.body(new ErrorResponse(e.getMessage()));
		}
	}
	
	// get all
	@GetMapping("/bookings")
	public ResponseEntity<List<BookingServiceDTO>> getAll() {
		return ResponseEntity.ok(bookingService.getAll());
	}
	
	@GetMapping("/booking/{id}")
	public ResponseEntity<?> get(@PathVariable(name = "id") Integer id) {
		BookingServiceDTO booking = bookingService.getOne(id);
		if (booking != null) {
			return ResponseEntity.ok(booking);
		}
		return ResponseEntity.notFound().build();
	}
	
	@DeleteMapping("/booking/{id}")
	public ResponseEntity<?> delete(@PathVariable(name = "id") Integer id) {
		try {
			bookingService.delete(id);
			return ResponseEntity.ok().build();
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
				.body(new ErrorResponse(e.getMessage()));
		}
	}
	
	@PutMapping("/booking")
	public ResponseEntity<?> update(@RequestBody BookingServiceDTO bookingServiceDTO) {
		try {
			bookingService.update(bookingServiceDTO);
			return ResponseEntity.ok().build();
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
				.body(new ErrorResponse(e.getMessage()));
		}
	}

    @GetMapping("/tour/{id}")
    public ResponseEntity<?> getTourInfo(@PathVariable int id) {
        TourDTO tour = bookingService.getTourDetails(id);
        if (tour != null) {
            return ResponseEntity.ok(tour);
        }
        return ResponseEntity.notFound().build();
    }

    @GetMapping("/booking/user/{userId}")
    public ResponseEntity<?> getBookingsByUserId(@PathVariable int userId) {
        try {
            List<BookingServiceDTO> bookings = bookingService.getAll().stream()
                .filter(booking -> booking.getUser_id() == userId)
                .collect(Collectors.toList());
            return ResponseEntity.ok(bookings);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorResponse(e.getMessage()));
        }
    }

    private static class ErrorResponse {
        private String message;

        public ErrorResponse(String message) {
            this.message = message;
        }

        public String getMessage() {
            return message;
        }

        public void setMessage(String message) {
            this.message = message;
        }
    }
}
