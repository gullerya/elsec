package com.gullerya.elsec;

import com.gullerya.elsec.api.SecurityService;
import org.junit.Test;

import javax.servlet.Filter;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpFilter;
import java.util.HashMap;
import java.util.Map;

public class FilterTest {

	@Test
	public void testA() throws ServletException {
		Filter f = new SecurityFilter();
		String[][] params = {{"secSerKey", SecurityService.DEFAULT_SEC_SER_KEY}};
		FilterConfig fc = new FilterConfigTest(params);
		f.init(fc);


	}

	private static final class FilterConfigTest extends HttpFilter {
		private Map<String, String> params = new HashMap<>();

		private FilterConfigTest(String[][] params) {
			for (String[] pair : params) {
				this.params.put(pair[0], pair[1]);
			}
		}

		@Override
		public String getInitParameter(String name) {
			return params.get(name);
		}
	}
}
