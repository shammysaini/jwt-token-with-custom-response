package com.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;


@Component
@Slf4j
public class JwtUtils {

	@Value("${jwt.secret}")
	private String secret;

	@Value("${jwt.expiration}")
	private long expiration;



	private SecretKey getSigningKey() {
		return Keys.hmacShaKeyFor(secret.getBytes());
	}

	public String generateToken(Authentication authentication,String username) {
		return Jwts.builder()
				.setSubject(username)
				.setIssuedAt(new Date())
				.setExpiration(new Date(System.currentTimeMillis() + expiration))
				.signWith(getSigningKey(), SignatureAlgorithm.HS256)  // Use SignatureAlgorithm.HS256
				.compact();
	}

	public boolean validateToken(String token) {
		try {
			Jwts.parser().verifyWith(getSigningKey()).build().parseSignedClaims(token);
			return true;
		} catch (JwtException e) {
			return false;
		}
	}

	public String extractUsername(String token) {
		return extractClaim(token, Claims::getSubject);
	}

	private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		Claims claims = Jwts.parser()
				.verifyWith(getSigningKey()).build()
				.parseSignedClaims(token)
				.getPayload();
		return claimsResolver.apply(claims);
	}
}