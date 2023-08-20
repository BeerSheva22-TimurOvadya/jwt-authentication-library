package telran.spring.security;

import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
@Component
@Slf4j
public class SecurityExceptionsHandler implements AuthenticationEntryPoint, AccessDeniedHandler {

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
			AccessDeniedException accessDeniedException) throws IOException, ServletException {
		log.error("authorization error for {}", request.getContextPath());
		response.addHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "*");
		response.setStatus(403);

	}

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {
		log.error("authentication error for {}", request.getContextPath());
		response.addHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "*");
		response.setStatus(401);
		
	}

	

}