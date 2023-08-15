package telran.spring.security;


import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;

import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

import telran.spring.security.jwt.JwtController;
import telran.spring.security.jwt.JwtFilter;
import telran.spring.security.jwt.JwtSecurityConfiguration;
import telran.spring.security.jwt.JwtUtil;
import telran.spring.security.jwt.dto.LoginData;
import telran.spring.security.jwt.dto.LoginResponse;

@SpringBootApplication
class RolesConfigurationTest implements RolesConfiguration {

	@Override
	public void configure(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.authorizeHttpRequests(
				custom -> custom.requestMatchers(HttpMethod.GET).authenticated().anyRequest().hasRole("ADMIN_TEST"));
	}

}

@WebMvcTest({ JwtFilter.class, JwtUtil.class, JwtController.class, JwtSecurityConfiguration.class,
		AccountingConfiguration.class, RolesConfigurationTest.class })
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class JwtAuthenticationTest {
	static String jwt;
	@Autowired
	MockMvc mockMvc;

	@Autowired
	JwtFilter jwtFilter;

	@Autowired
	JwtUtil jwtUtil;

	@Autowired
	UserDetailsService userDetailsService;

	ObjectMapper mapper = new ObjectMapper();
	LoginData loginData = new LoginData("admin", "pppp");

	@Test
	void authenticationErrorTest() throws Exception {
		mockMvc.perform(get("http://localhost:8080/kuku")).andDo(print()).andExpect(status().isUnauthorized());
	}

	@Test
	@Order(1)
	void loginTest() throws Exception {
		String loginResponseJson = mockMvc
				.perform(post("http://localhost:8080/login").contentType(MediaType.APPLICATION_JSON)
						.content(mapper.writeValueAsString(loginData)))
				.andDo(print()).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
		LoginResponse loginResponse = mapper.readValue(loginResponseJson, LoginResponse.class);
		jwt = loginResponse.accessToken();
	}

	@Test
	@Order(2)
	void authenticationNormalTest() throws Exception {
		mockMvc.perform(get("http://localhost:8080/kuku").header("Authorization", "Bearer " + jwt)).andDo(print())
				.andExpect(status().isNotFound());

	}

	@Test
	@Order(3)
	void authenticationExpiredTest() throws Exception {
		Thread.sleep(2500);
		mockMvc.perform(get("http://localhost:8080/kuku").header("Authorization", "Bearer " + jwt)).andDo(print())
				.andExpect(status().isUnauthorized());

	}

}
