package com.amigo.securities.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

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

    // 用于从数据库中获取用户
    @Override
    @Bean // 用于SpringBoot帮助我们自动注入
    protected UserDetailsService userDetailsService() {
        UserDetails kobeBryant = User.builder()
                .username("kobebryant")
                .password(passwordEncoder.encode("password123"))
                .roles(ApplicationUserRole.STUDENT.name()) // spring 会将roles转换成 ROLE_STUDENT
                .build();

        UserDetails lindaUser = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("password123"))
                .roles(ApplicationUserRole.ADMIN.name())
                .build();

        return new InMemoryUserDetailsManager(kobeBryant, lindaUser);

    }
}
