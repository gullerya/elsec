package com.gullerya.elsec;

import com.gullerya.elsec.api.SecurityService;
import com.gullerya.elsec.impl.SecurityConfigurationDefault;
import com.gullerya.elsec.impl.SecurityFactory;
import org.junit.Assert;
import org.junit.Test;

import javax.servlet.Filter;
import javax.servlet.FilterConfig;
import javax.servlet.http.HttpFilter;
import java.util.HashMap;
import java.util.Map;

public class FilterTest {

	@Test
	public void testA() throws Exception {
		Filter f = new SecurityFilter();
		String[][] params = {
				{SecurityService.SERVICE_PARAM_KEY, SecurityService.DEFAULT_SEC_SER_KEY},
				{SecurityService.SERVICE_CONFIG_KEY, "com.gullerya.elsec.FilterTest$TestSecConfig"}
		};
		FilterConfig fc = new FilterConfigTest(params);
		f.init(fc);

		SecurityService securityService = SecurityFactory.obtain(SecurityService.DEFAULT_SEC_SER_KEY, null);
		Assert.assertNotNull(securityService);
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

	private static final class TestSecConfig extends SecurityConfigurationDefault {

		TestSecConfig() throws Exception {
			super();
		}

		@Override
		public String getPass() {
			return "pass-phrase";
		}
	}
}
