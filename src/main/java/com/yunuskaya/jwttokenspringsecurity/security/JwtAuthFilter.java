package com.yunuskaya.jwttokenspringsecurity.security;

import com.yunuskaya.jwttokenspringsecurity.service.JwtService;
import com.yunuskaya.jwttokenspringsecurity.service.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Slf4j
public class JwtAuthFilter extends OncePerRequestFilter { /* OncePerRequestFilter ile her requestte bir kez çalışmasını sağlıyoruz. */


    private final JwtService jwtService;
    private final UserService userService;

    public JwtAuthFilter(JwtService jwtService, UserService userService) {
        this.jwtService = jwtService;
        this.userService = userService;
    }

    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException { /* request ve response objelerini alıp filterChain ile bir sonraki filtreye gönderiyoruz. */
        String authHeader = request.getHeader("Authorization"); /* requestin headerından Authorization bilgisini alıyoruz. */
        String token = null; /* token bilgisini tutmak için bir değişken oluşturuyoruz. */
        String username = null; /* kullanıcı adını tutmak için bir değişken oluşturuyoruz. */
        if (authHeader != null && authHeader.startsWith("Bearer ")) { /* Authorization bilgisi varsa ve başlangıcı Bearer ise */
            token = authHeader.substring(7); /* token bilgisini alıyoruz. */
            username = jwtService.extractUser(token); /* token içerisindeki kullanıcı adını alıyoruz. */
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) { /* kullanıcı adı varsa ve kullanıcı daha önce kimlik doğrulaması yapmamışsa */
            UserDetails user = userService.loadUserByUsername(username); /* kullanıcı adına göre kullanıcı bilgilerini alıyoruz. */
            log.info("user loaded " + user); /* kullanıcı bilgilerini logluyoruz. */
            if (jwtService.validateToken(token, user)) { /* token doğrulama işlemi yapıyoruz. */
                log.info("token is validated" + token); /* token doğrulama işlemi başarılıysa logluyoruz. */
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities()); /* kullanıcı bilgileri ve yetkileri ile bir authentication token oluşturuyoruz. */
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request)); /* authentication tokena request bilgilerini ekliyoruz. */
                SecurityContextHolder.getContext().setAuthentication(authToken); /* authentication tokenı security contexte ekliyoruz. */
            }
        }

        filterChain.doFilter(request, response); /* bir sonraki filtreye request ve response objelerini gönderiyoruz. */
    }


}
