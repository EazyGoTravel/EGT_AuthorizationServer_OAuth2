package com.egt.oauth2.config;

import java.security.NoSuchAlgorithmException;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;

import com.egt.oauth2.keys.KeyManager;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
public class OAuth2ServerConfig {

	private final KeyManager keyManager;

	public OAuth2ServerConfig(KeyManager keyManager) {
		this.keyManager = keyManager;
	}

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);
		return httpSecurity.formLogin().and().build();
	}

	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		var registeredClient = RegisteredClient.withId(UUID.randomUUID().toString()).clientId("egt-app")
				.clientSecret("secrect").authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST).scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE).redirectUri("http://localhost:8091").authorizationGrantTypes(gt -> {
					gt.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
					gt.add(AuthorizationGrantType.AUTHORIZATION_CODE);
					gt.add(AuthorizationGrantType.REFRESH_TOKEN);
				}).build();

		return new InMemoryRegisteredClientRepository(registeredClient);
	}

	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}

	@Bean
	public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
		var jwkSet = new JWKSet(keyManager.rsaKey());
		return (j, sc) -> j.select(jwkSet);
	}
}
