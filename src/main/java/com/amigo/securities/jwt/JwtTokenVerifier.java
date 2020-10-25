package com.amigo.securities.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class JwtTokenVerifier extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain
    ) throws ServletException, IOException {
        // 得到客户端请求头中的 Authentication
        String authenticationHeader = request.getHeader("Authentication");
        String secretKey = "whatever---you***want***just***be**security";

        if (Strings.isNullOrEmpty(authenticationHeader) || !authenticationHeader.startsWith("Bearer ")) {
            // 如果为空 或者不是以 `Bearer ` 开头的 则说明不包含Authentication
            chain.doFilter(request, response); // 直接传给下一个filter处理（如果存在的话）
            // 一般这里都会返回 403 给客户端
            return;
        }

        try {
            // 将"Bearer "去掉得到真正的token
            String token = authenticationHeader.replace("Bearer ", "");

            Jws<Claims> claimsJws = Jwts.parserBuilder()
                    .setSigningKey(Keys.hmacShaKeyFor(secretKey.getBytes()))
                    .build()
                    .parseClaimsJws(token);
            Claims body = claimsJws.getBody();
            String username = body.getSubject(); // 之前签发token时将username设置到了subject中,现在取回
            // 取回jwt payload中的 `authorities` 字段
            var authorities = (List<Map<String, String>>) body.get("authorities");

            Set<SimpleGrantedAuthority> simpleGrantedAuthorities = authorities.stream()
                    .map(m -> new SimpleGrantedAuthority(m.get("authority")))
                    .collect(Collectors.toSet());

            // UsernamePasswordAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities)
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    simpleGrantedAuthorities
            );

            // 验证
            SecurityContextHolder.getContext().setAuthentication(authentication);

        } catch (JwtException e) {
            // 一般这里都会返回 403 给客户端
            throw new IllegalStateException("无效Token");
        }
        // 把filter后的结果传递给下一个filter 类似expressjs中的中间件
        chain.doFilter(request, response);
    }
}
