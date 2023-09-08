package com.devsuperior.dscatalog.repositories;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.devsuperior.dscatalog.entities.Product;
import com.devsuperior.dscatalog.projections.ProductProjection;

@Repository
public interface ProductRepository extends JpaRepository<Product, Long> {

	/**
	 * Avoid N+1 problem, search for the products that are going to be part of the
	 * page. Later we can use these id's to use as arguments of the query that will
	 * search for products and their respective categories.
	 * 
	 * @param categoryIds
	 * @param name
	 * @param pageable
	 * @return
	 */
	@Query(nativeQuery = true, value = """
			SELECT * FROM (
			SELECT DISTINCT tb_product.id, tb_product.name
			FROM tb_product
			INNER JOIN tb_product_category ON tb_product_category.product_id = tb_product.id
			WHERE (:categoryIds IS NULL OR tb_product_category.category_id IN :categoryIds)
			AND LOWER(tb_product.name) LIKE LOWER(CONCAT('%',:name,'%'))
			) as tb_result
			""",
			countQuery = """
			SELECT COUNT(*) FROM (
			SELECT DISTINCT tb_product.id, tb_product.name
			FROM tb_product
			INNER JOIN tb_product_category ON tb_product_category.product_id = tb_product.id
			WHERE (:categoryIds IS NULL OR tb_product_category.category_id IN :categoryIds)
			AND LOWER(tb_product.name) LIKE LOWER(CONCAT('%',:name,'%'))
			) AS tb_result
			""")
	Page<ProductProjection> sarchProducts(List<Long> categoryIds, String name, Pageable pageable);
	
	@Query("SELECT obj FROM Product obj JOIN FETCH obj.categories WHERE obj.id IN :productIds")
	List<Product> searchProductsWithCategories(List<Long> productIds);

}
