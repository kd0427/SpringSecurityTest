package com.security.jwttest.service;

import com.security.jwttest.entity.User;
import com.security.jwttest.jwt.JwtFilter;
import com.security.jwttest.repository.UserRepository;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Component("userDetailsService")
public class CustomUserDetailsService implements UserDetailsService {

    private static final Logger logger = LoggerFactory.getLogger(CustomUserDetailsService.class);

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository){
        this.userRepository = userRepository;
    }

    @Override
    @Transactional //데이터베이스를 다룰 때 트랜잭션을 적용하면 데이터 추가, 갱신, 삭제 등으로 이루어진 작업을 처리하던 중
                    // 오류가 발생했을 때 모든 작업들을 원상태로 되돌릴 수 있다.
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findOneWithAuthoritiesByUsername(username)
                .map(user -> createUser(username, user))
                .orElseThrow(() ->{
                    logger.debug("사용자 아이디가 없습니다.");
                    return new UsernameNotFoundException(username+ "-> 데이터베이스에서 찾을 수 없습니다.");
                } );
        // login 시 입력한 아이디로 유저정보와 권한이 담겨있는 user 객체를 가져오고
        // 가져온 user 객체와 입력한 아이디를 매개변수로 createUser 메소드를 실행해서
        // user 객체를 createUser 메소드로 만든 UserDetails 객체로 바꿔준다. SpringSecurity 는 UserDetails 객체만 처리가능
        // 값이 없으면 UsernameNotFoundException
    }

    private org.springframework.security.core.userdetails.User createUser(String username, User user){
        if(!user.isActivated()){
            logger.debug("아이디가 활성화 되어 있지 않습니다.");
            throw new RuntimeException(username + "=-> 활성화되어 있지 않습니다.");
        }
        List<GrantedAuthority> grantedAuthorities = user.getAuthorities().stream()
                .map(authority -> new SimpleGrantedAuthority(authority.getAuthorityName())) // 가져온 user 의 권한 이름으로 권한객체 생성
                .collect(Collectors.toList());
        logger.debug("UserDetails 로 만들어줌");
        return new org.springframework.security.core.userdetails.User(user.getUsername(),user.getPassword(),grantedAuthorities);
        // SpringSecurity 가 처리 가능한 형태인  UserDetails 로 반환
    }
}
