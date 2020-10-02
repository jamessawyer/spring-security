package com.amigo.securities.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 表示 任何请求都需要验证 并且 使用 basic auth
        http
            .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*")
                .permitAll()
            .anyRequest()
            .authenticated()
            .and()
            .httpBasic();
    }
}
