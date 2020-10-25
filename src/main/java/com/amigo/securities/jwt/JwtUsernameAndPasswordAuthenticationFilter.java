package com.amigo.securities.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDate;
import java.util.Date;

public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws AuthenticationException {
        try {
            UsernameAndPasswordAuthenticationRequest authenticationRequest =
                new ObjectMapper().readValue(request.getInputStream(), UsernameAndPasswordAuthenticationRequest.class);

            // UsernamePasswordAuthenticationToken(Object principal, Object credentials)
            // username 表示 principal, password credentials
            // UsernamePasswordAuthenticationToken 是 Authentication接口的实现类
            Authentication authenticationToken = new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getUsername(),
                    authenticationRequest.getPassword()
            );

            // 使用 authenticationManager.authenticate 方法
            Authentication authenticate = authenticationManager.authenticate(authenticationToken);
            return authenticate;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain,
            Authentication authResult
    ) throws IOException, ServletException {
        // 什么key都可以 确保安全 不要泄漏
        String secretKey = "whatever---you***want***just***be**security";

        String token = Jwts.builder()
                // 下面都是添加到JWT payload 中的信息
                .setSubject(authResult.getName())
                .claim("authorities", authResult.getAuthorities()) // 添加权限信息
                .setIssuedAt(new Date()) // 签发时间
                .setExpiration(java.sql.Date.valueOf(LocalDate.now().plusWeeks(2))) // 设置过期时间为2个星期
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes())) // 加密 key
                .compact();

        // 将生成的token 发送给客户端
        // 一般会通过返回值的形式，这里为了演示，将其添加到header中返回
        response.addHeader("Authentication", "Bearer " + token);
    }
}
