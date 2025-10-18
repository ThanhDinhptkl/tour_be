package com.tour.bookingservice.entities;

import java.util.Collection;
import java.util.Collections;
import java.util.Date;



import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;


import lombok.Data;

@Entity
@Table(name = "Booking")
@Data
public class Booking {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private int id;

	@Column(name = "user_id")
	private int user_id;

	@Column(name = "tour_id")
	private int tour_id;

	@Column(name = "booking_date")
	private Date booking_date;

	@Enumerated(EnumType.STRING)
	@Column(name = "status", nullable = false)
	private Status status;



	@Column(name = "number_of_people")
	private int number_of_people;

	@Column(name = "total_price")
	private double total_price;

	@Column(name = "created_at")
	private Date created_at;

	public Booking() {
		super();
		// TODO Auto-generated constructor stub
	}
	public enum Status {
		PENDING, CONFIRMED, CANCELLED
	}

	public Booking(int id, int user_id, int tour_id, Date booking_date, Status status, int number_of_people,
			double total_price, Date created_at) {
		super();
		this.id = id;
		this.user_id = user_id;
		this.tour_id = tour_id;
		this.booking_date = booking_date;
		this.status = status;
		this.number_of_people = number_of_people;
		this.total_price = total_price;
		this.created_at = created_at;
	}


	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

	public int getUser_id() {
		return user_id;
	}

	public void setUser_id(int user_id) {
		this.user_id = user_id;
	}

	public int getTour_id() {
		return tour_id;
	}

	public void setTour_id(int tour_id) {
		this.tour_id = tour_id;
	}

	public Date getBooking_date() {
		return booking_date;
	}

	public void setBooking_date(Date booking_date) {
		this.booking_date = booking_date;
	}

	public Status getStatus() {
		return status;
	}
	
	public void setStatus(Status status) {
		this.status = status;
	}

	public int getNumber_of_people() {
		return number_of_people;
	}

	public void setNumber_of_people(int number_of_people) {
		this.number_of_people = number_of_people;
	}

	public double getTotal_price() {
		return total_price;
	}

	public void setTotal_price(double total_price) {
		this.total_price = total_price;
	}

	public Date getCreated_at() {
		return created_at;
	}

	public void setCreated_at(Date created_at) {
		this.created_at = created_at;
	}

}
