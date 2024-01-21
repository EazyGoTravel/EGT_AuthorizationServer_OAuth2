package com.egt.oauth2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class WebSecurityConfig {

	@Bean
	public SecurityFilterChain webSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
		return httpSecurity.formLogin().and().authorizeRequests().anyRequest().authenticated().and().build();
	}

	@Bean
	public PasswordEncoder encoder() {
		return NoOpPasswordEncoder.getInstance();
	}

	@Bean
	public UserDetailsService userDetailsService() {
		var userDetails = User.withUsername("neehar").password("neehar").authorities("read").build();
		return new InMemoryUserDetailsManager(userDetails);
	}
}
