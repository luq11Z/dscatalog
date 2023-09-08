package com.devsuperior.dscatalog.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.devsuperior.dscatalog.projections.IdProjection;

public class Utils {

	/**
	 * Order list given the order provided from the page.
	 * @param content
	 * @param entities
	 * @return
	 */
	public static <ID> List<? extends IdProjection<ID>> replace(List<? extends IdProjection<ID>> ordered, 
			List<? extends IdProjection<ID>> unordered) {
		Map<ID, IdProjection<ID>> map = new HashMap<>();
		
		// using map to improve efficiency
		for (IdProjection<ID> product : unordered) {
			map.put(product.getId(), product);
		}
		
		List<IdProjection<ID>> result = new ArrayList<>();
		
		// fill the new list with the correct order
		for (IdProjection<ID> obj : ordered) { 
			result.add(map.get(obj.getId()));
		}
		
		return result;
	}

}
