package telran.spring.security.jwt;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtil {
	@Value("${app.jwt.signature.secret}")
	String key ;
	@Value("${app.jwt.expiration.period:3600000}")
	long expPeriod;
public String extractUserName(String token) {
	
	return extractClaim(token, Claims::getSubject);
}
public Date extractExpirationDate(String token) {
	
	return extractClaim(token, Claims::getExpiration);
}
private Claims extractAllClaims(String token) {
	return Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token).getBody();
}
public <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
	return claimResolver.apply(extractAllClaims(token));
}
private Key getSigningKey() {
	byte[] keyBytes = Decoders.BASE64.decode(key);
	return Keys.hmacShaKeyFor(keyBytes);
}

public String createToken(UserDetails userDetails) {
	
	return createToken(new HashMap<>(), userDetails);
}
public String createToken(Map<String, Object> extraClaims, UserDetails userDetails) {
	String[] roles = userDetails.getAuthorities().stream().map(auth -> auth.getAuthority().replace("ROLE_", "")).toArray(String[]::new);
	extraClaims.put("roles", roles);
	Date current = new Date();
	Date exp = new Date(System.currentTimeMillis() + expPeriod);
	return Jwts.builder().addClaims(extraClaims).setExpiration(exp).setIssuedAt(current)
			.setSubject(userDetails.getUsername()).signWith(getSigningKey(), SignatureAlgorithm.HS256).compact();
}
@SuppressWarnings("unchecked")
public List<String> extractRoles(String token) {
	return  (List<String>) extractClaim(token, claims -> claims.get("roles"));
}
}