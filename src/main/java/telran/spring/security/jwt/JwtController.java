package telran.spring.security.jwt;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import telran.spring.security.jwt.dto.LoginData;
import telran.spring.security.jwt.dto.LoginResponse;

@RestController
@RequestMapping("/login")
@RequiredArgsConstructor
@CrossOrigin
public class JwtController {
	final UserDetailsService userDetailsService;
	final PasswordEncoder passwordEncoder;
	final JwtUtil jwtUtil;
	@PostMapping
	LoginResponse login(@RequestBody @Valid LoginData loginData) {
		try {
			String username = loginData.username();
			String password = loginData.password();
			UserDetails userDetails = userDetailsService.loadUserByUsername(username);
			if (userDetails == null || !userDetails.isAccountNonExpired()) {
				throw new IllegalArgumentException("Account expired");
			}
			if(!passwordEncoder.matches(password, userDetails.getPassword())) {
				throw new IllegalArgumentException("Wrong Credentials");
			}
			return new LoginResponse(jwtUtil.createToken(userDetails));
			
		} catch(UsernameNotFoundException e) {
			throw new IllegalArgumentException("Wrong credentials: " + e.getMessage());
		}
	}
}