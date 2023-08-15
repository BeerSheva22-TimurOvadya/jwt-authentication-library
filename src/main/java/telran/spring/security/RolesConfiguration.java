package telran.spring.security;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public interface RolesConfiguration {
void configure(HttpSecurity httpSecurity) throws Exception;
}
