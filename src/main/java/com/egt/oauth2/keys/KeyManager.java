package com.egt.oauth2.keys;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import org.springframework.stereotype.Component;

import com.nimbusds.jose.jwk.RSAKey;

@Component
public class KeyManager {

	private static KeyManager instance;

	private KeyManager() {

	}

	public static KeyManager getInstance() {
		synchronized (instance) {
			if (instance == null) {
				instance = new KeyManager();

			}
			return instance;
		}

	}

	public RSAKey getRSAKey() throws NoSuchAlgorithmException {

		var kpGen = KeyPairGenerator.getInstance("RSA");
		kpGen.initialize(2048);

		var keyPair = kpGen.generateKeyPair();

		var pubKey = (RSAPublicKey) keyPair.getPublic();
		var privKey = (RSAPrivateKey) keyPair.getPrivate();
		return new RSAKey.Builder(pubKey).privateKey(privKey).keyID(UUID.randomUUID().toString()).build();

	}
}