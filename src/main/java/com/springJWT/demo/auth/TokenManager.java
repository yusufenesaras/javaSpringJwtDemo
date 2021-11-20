package com.springJWT.demo.auth;

import java.security.Key;
import java.util.Date;

import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Service
public class TokenManager {
	
	private static final int validaty = 5*60*1000; // 5 dakika süre
	Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
	
	public String generateToken(String username){
		return Jwts.builder()
				.setSubject(username)
				.setIssuer("yusufenesaras.netlify.app")
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis()+ validaty))
				.signWith(key)
				.compact();
	}
	
	public boolean tokenValidate(String token){
		if(getUsernameToken(token) != null && isExpired(token)) {
			return true;
		}else {
			return false;
		}
	}
	
	public String getUsernameToken(String token){
		Claims claims = getClaims(token);
		return claims.getSubject();
	}
	
	public boolean isExpired(String token){
		Claims claims = getClaims(token);
		return claims.getExpiration().after(new Date(System.currentTimeMillis()));
	}

	private Claims getClaims(String token) {
		return Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody();
		 
	}
	
}
