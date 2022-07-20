package com.security.jwttest.controller;

import com.security.jwttest.dto.LoginDTO;
import com.security.jwttest.dto.TokenDTO;
import com.security.jwttest.jwt.JwtFilter;
import com.security.jwttest.jwt.TokenProvider;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@RequestMapping("/api")
@AllArgsConstructor // 모든 필드변수를 매개변수로 갖는 생성자 메소드 생성해줌
public class AuthController {

    private final TokenProvider tokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

//    public AuthController(TokenProvider tokenProvider, AuthenticationManagerBuilder authenticationManagerBuilder){
//        this.tokenProvider = tokenProvider;
//        this.authenticationManagerBuilder = authenticationManagerBuilder;
//    }

    @PostMapping("/authenticate")
    //ResponseEntity 는 사용자의 HttpRequest 에 대한 응답 데이터를 포함하는 클래스이다.
    // 따라서 HttpStatus, HttpHeaders, HttpBody 를 포함한다.
    public ResponseEntity<TokenDTO> authorize(@Valid @RequestBody LoginDTO loginDTO){
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDTO.getUsername(),loginDTO.getPassword());
        // 사용자가 입력한 아이디와 비밀번호로 아직 인증되지않은 authenticationToken 객체 생성

        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        // authenticate() 메소드로 인증 되지않은 authenticationToken 객체를 인증 검사 한 후
        // 통과하면 authentication 라는 인증된 객체 생성
        SecurityContextHolder.getContext().setAuthentication(authentication);
        // SecurityContext 에 authentication 객체 저장

        String jwt = tokenProvider.createToken(authentication);
        // 인증된 authentication 을 이용해 jwt 토큰 생성

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer "+ jwt);
        // HttpHeader 의 Authorization (key) 은 Bearer + jwt 토큰(value) 저장

        return new ResponseEntity<>(new TokenDTO(jwt), httpHeaders, HttpStatus.OK);
        // body , header, status
    }
}
