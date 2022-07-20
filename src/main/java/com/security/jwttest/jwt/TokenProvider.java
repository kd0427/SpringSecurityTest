package com.security.jwttest.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class TokenProvider implements InitializingBean { //토큰의 생성, 토큰의 유효성 검증등을 담당

    private final Logger logger = LoggerFactory.getLogger(TokenProvider.class);

    private static final String AUTHORITIES_KEY = "auth";

    private final String secret;
    private final long tokenValidityInMilliseconds;

    private Key key;


    public TokenProvider(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.token-validity-in-seconds}") long tokenValidityInSeconds) {
        this.secret = secret;
        this.tokenValidityInMilliseconds = tokenValidityInSeconds * 1000;
    } // secret 과 tokenValidityInMilliseconds 에 yml 파일에 있는 jwt 값 주입

    @Override
    public void afterPropertiesSet() { // secret 값을 Base64 Decode 해서 key 변수에 할당
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    public String createToken(Authentication authentication) { // authentication 객체의 권한정보를 이용해 토큰을 생성하는 메소드
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        long now = (new Date()).getTime();
        Date validity = new Date(now + this.tokenValidityInMilliseconds); // yml 에 설정한 만료시간

        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities)
                .signWith(key, SignatureAlgorithm.HS512)
                .setExpiration(validity)
                .compact();  // jwt 토큰을 생성해서 return
    }

    public Authentication getAuthentication(String token) { // Token 에 담겨있는 정보를 이용해 Authentication 객체를 리턴하는 메소드
        Claims claims = Jwts     // 토큰으로 클래임을 만들고 // claim 이란 토큰 안에 사용자의 정보나 권한이 들어있음 서버에 저장하지 않음
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList()); // 토큰으로 만든 클래임에서 권한정보들을 빼낸다.

        User principal = new User(claims.getSubject(), "", authorities); // 권한 정보들( authorities )을 이용해
                                                                                    // User principal 객체 생성

        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
                                                    // User 객체와 토큰 ,권한 정보들을 이용해 Authentication 객체를 리턴
    }

    public boolean validateToken(String token) { // jwt 토큰의 유효성 검사

        try {   // 파라미터로 받은 token 을 parsing 해보고 발생하는 익셉션들을 캐치 정상이면 true, 아니면 false
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            logger.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            logger.info("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            logger.info("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            logger.info("JWT 토큰이 잘못되었습니다.");
        }
        return false;
    }
}