package com.generation.mercadela.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.generation.mercadela.model.Product;

@Repository
public interface ProductRepository extends JpaRepository<Product, Long> {

    @Query("SELECT p FROM Product p WHERE p.user.id = :userId")
    List<Product> findProductsForUser(@Param("userId") Long userId);

    @Query("SELECT p FROM Product p WHERE LOWER(p.name) LIKE LOWER(CONCAT('%', :term, '%'))")
    List<Product> findByTerm(@Param("term") String term);
}
