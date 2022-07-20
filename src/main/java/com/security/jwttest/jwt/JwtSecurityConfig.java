package com.security.jwttest.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
public class JwtSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
    // TokenProvider, JwtFilter 를 SecurityConfig 에 적용할때 사용할 클래스

    private TokenProvider tokenProvider;

    public JwtSecurityConfig(TokenProvider tokenProvider) { // 생성자 메소드
        this.tokenProvider = tokenProvider;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {

        JwtFilter customFilter = new JwtFilter(tokenProvider); // tokenProvider 를 주입받아서 JwtFilter 를 생성하고
        http.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class); // Security 로직에  생성한 필터 등록
    }
}
