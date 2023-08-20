package telran.spring.security.jwt;

import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtFilter extends OncePerRequestFilter {
 private static final String BEARER = "Bearer ";
final JwtUtil jwtUtil;
 final UserDetailsService userDetailsService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		String jwt = getJwt(request);
		log.trace("jwt from header is {}", jwt == null ? "null" : jwt);
		if (jwt != null) {
			try {
				String username = jwtUtil.extractUserName(jwt);
				UserDetails userDetails = userDetailsService.loadUserByUsername(username);
				log.trace("extracted username is {} ", username);
				if (userDetails == null || !userDetails.isAccountNonExpired()) {
					throw new UsernameNotFoundException(username);
				}
				UsernamePasswordAuthenticationToken authentication =
						new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(authentication);
				log.trace("security context is established");
			} catch (Throwable e) {
				log.error("error {}", e.getMessage());
				
			}
			
		}
		filterChain.doFilter(request, response)	;	

	}

	private String getJwt(HttpServletRequest request) {
		String authHeader = request.getHeader("Authorization");
		String res = null;
		if (authHeader != null && authHeader.startsWith(BEARER)) {
			res = authHeader.substring(BEARER.length());
		}
		return res;
	}

}