package com.tour.tourservice.service;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import com.tour.tourservice.dto.TourDTO;
import com.tour.tourservice.model.Tour;
import com.tour.tourservice.repository.TourRepository;

public interface TourService {
	void add(TourDTO tourDTO);
	
	//add list tour
	void addList(List<TourDTO> tourDTOs);

	void update(TourDTO tourDTO);

	void delete(int id);

	List<TourDTO> getAll();
	
	List<Tour> findByLocation(String location);
	
	List<Tour> findByTitle(String title);

	TourDTO getOne(int id);
	
	List<Tour> findByPriceRange(double minPrice, double maxPrice);
	
	String uploadTourImage(MultipartFile file);
}

@Transactional
@Service
class TourServiceImpl implements TourService {
	
	@Autowired
	TourRepository tourRepository;
	
	@Autowired
	ModelMapper modelMapper;
	
	@Autowired
	CloudinaryService cloudinaryService;
	
	
	@Override
	public void add(TourDTO tourDTO) {
		Tour tour = modelMapper.map(tourDTO, Tour.class);	
		tourRepository.save(tour);
		tourDTO.setId_tour(tour.getId_tour());          
		// TODO Auto-generated method stub

	}

	@Override
	public void update(TourDTO tourDTO) {
		Tour tour = tourRepository.getById(tourDTO.getId_tour());
		if (tour != null) {
			modelMapper.typeMap(TourDTO.class, Tour.class)
			.addMappings(mapper -> mapper.skip(Tour::setCreated_at))
			.map(tourDTO, tour);
			tourRepository.save(tour);
		}
		// TODO Auto-generated method stub

	}

	@Override
	public void delete(int id) {
		Tour tour = tourRepository.getById(id);
		if (tour != null) {
			tourRepository.delete(tour);
		}
		// TODO Auto-generated method stub

	}

	@Override
	public List<TourDTO> getAll() {
		List<TourDTO> tourDTOs = new ArrayList<>();
		tourRepository.findAll().forEach((tour) -> {
			tourDTOs.add(modelMapper.map(tour, TourDTO.class));
		});
		// TODO Auto-generated method stub
		return tourDTOs;
	}

	@Override
	public TourDTO getOne(int id) {
		Tour tour = tourRepository.getById(id);
		if (tour != null) {
            return modelMapper.map(tour, TourDTO.class);
		// TODO Auto-generated method stub
	}
		return null;
	}

	@Override
	public void addList(List<TourDTO> tourDTOs) {
		// TODO Auto-generated method stub
		for (TourDTO tourDTO : tourDTOs) {
			Tour tour = modelMapper.map(tourDTO, Tour.class);
			tourRepository.save(tour);
			tourDTO.setId_tour(tour.getId_tour());
		}
		
	}

	@Override
	public List<Tour> findByLocation(String location) {
		// TODO Auto-generated method stub
		
		return tourRepository.findByLocation(location);
	}

	@Override
	public List<Tour> findByTitle(String title) {
	    return tourRepository.findAll().stream()
	            .filter(tour -> tour.getTitle().toLowerCase().contains(title.toLowerCase()))
	            .collect(Collectors.toList());
	}

	@Override
	public List<Tour> findByPriceRange(double minPrice, double maxPrice) {
	    if (minPrice > maxPrice) {
	        throw new IllegalArgumentException("minPrice phải nhỏ hơn hoặc bằng maxPrice");
	    }
	    return tourRepository.findByPriceBetween(minPrice, maxPrice).stream()
	            .sorted((t1, t2) -> Double.compare(t1.getPrice(), t2.getPrice())) // Sắp xếp tăng dần
	            .collect(Collectors.toList());
	}

	@Override
	public String uploadTourImage(MultipartFile file) {
		return cloudinaryService.uploadImage(file);
	}

}
