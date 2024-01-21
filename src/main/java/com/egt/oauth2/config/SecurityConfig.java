package com.egt.oauth2.config;

import java.security.NoSuchAlgorithmException;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import com.egt.oauth2.keys.KeyManager;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain webSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);
		httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());
		httpSecurity.exceptionHandling(e -> e.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));
		return httpSecurity.build();
	}

	@Bean
	@Order(2)
	public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.authorizeHttpRequests(req -> req.anyRequest().authenticated())
				.formLogin(Customizer.withDefaults());
		return httpSecurity.build();
	}

	@Bean
	public UserDetailsService userDetailsService() {
		var userDetails = User.withUsername("neehar").password("neehar").authorities("read").build();
		return new InMemoryUserDetailsManager(userDetails);
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}

	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		// @formatter:off
		var registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("egt-app")
				.clientSecret("secrect")
				.scopes(scopes->{
					scopes.add(OidcScopes.PROFILE);
					scopes.add(OidcScopes.OPENID);
				})
				.redirectUri("http://localhost:8091")
				.clientAuthenticationMethods(clientAuthmethods->{
					clientAuthmethods.add(ClientAuthenticationMethod.NONE);
					clientAuthmethods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
					clientAuthmethods.add(ClientAuthenticationMethod.CLIENT_SECRET_POST);
				})
				.authorizationGrantTypes(gt -> {
					gt.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
					gt.add(AuthorizationGrantType.AUTHORIZATION_CODE);
					gt.add(AuthorizationGrantType.REFRESH_TOKEN);
				})
				.clientSettings(ClientSettings.builder().requireProofKey(true).build())
				.build();
		// @formatter:on

		return new InMemoryRegisteredClientRepository(registeredClient);
	}

	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}

	public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {

		var rsaKey = KeyManager.getInstance().getRSAKey();
		var jwkSet = new JWKSet(rsaKey);
		return new ImmutableJWKSet<>(jwkSet);
	}

	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}
}
