package com.yunuskaya.jwttokenspringsecurity.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtService {

    @Value("${jwt.key}")
    private String SECRET; /* application.properties dosyasındaki jwt.secret değerini alıyoruz */

    public String generateToken(String username) { /* token oluşturuyoruz */
        Map<String, Object> claims = new HashMap<>(); /* token içerisine eklemek istediğimiz bilgileri map olarak tutuyoruz */
        return createToken(claims, username); /* token oluşturmak için createToken metodunu çağırıyoruz */
    }
    public boolean validateToken(String token,UserDetails  userDetails) { /* tokeni doğruluyoruz */
        String username = extractUser(token); /* token içerisindeki kullanıcı adını alıyoruz */
        Date expirationDate = extractExpiration(token); /* tokenin geçerlilik süresini alıyoruz */
        return userDetails.getUsername().equals(username) && !expirationDate.before(new Date());/* tokenin geçerlilik süresi dolmadıysa ve tokenin sahibi doğruysa true döndürüyoruz */
    }

    private Date extractExpiration(String token) { /* tokenin geçerlilik süresini alıyoruz */
        Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.getExpiration();
    }
    public String extractUser(String token) { /* token içerisindeki kullanıcı adını alıyoruz */
        Claims claims = Jwts
                .parserBuilder() /* tokeni parse etmek için Jwts sınıfının parserBuilder metodunu kullanıyoruz */
                .setSigningKey(getSignKey()) /* tokeni imzalarken kullandığımız keyi belirtiyoruz */
                .build()  /* tokeni parse etmek için build metodunu çağırıyoruz */
                .parseClaimsJws(token) /* tokeni parse ediyoruz */
                .getBody(); /* token içerisindeki bilgileri almak için Jwts sınıfının parserBuilder metodunu kullanıyoruz */
        return claims.getSubject(); /* tokenin sahibini döndürüyoruz */
    }



    private String createToken( Map<String, Object > claims, String username){ /* token oluşturuyoruz */
        return Jwts.builder() /* token oluşturmak için Jwts sınıfının builder metodunu kullanıyoruz */
                .setClaims(claims) /* token içerisine eklemek istediğimiz bilgileri ekliyoruz */
                .setSubject(username) /* tokenin sahibini belirtiyoruz */
                .setIssuedAt(new Date(System.currentTimeMillis())) /* tokenin oluşturulma tarihini belirtiyoruz */
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 2)) /* (tokenin geçerlilik süresini belirtiyoruz */
                .signWith(getSignKey(), SignatureAlgorithm.HS256) /* tokeni imzalıyoruz */
                .compact(); /* tokeni oluşturuyoruz */
    }

    private Key getSignKey(){
        byte[] keyBytes = Decoders.BASE64.decode(SECRET); /* secret keyi base64 den byte dizisine çeviriyoruz */
        return Keys.hmacShaKeyFor(keyBytes); /* byte dizisini keye çeviriyoruz */
    }
}
