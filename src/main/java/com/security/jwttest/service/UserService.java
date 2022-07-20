package com.security.jwttest.service;

import com.security.jwttest.dto.UserDTO;
import com.security.jwttest.entity.Authority;
import com.security.jwttest.entity.User;
import com.security.jwttest.repository.UserRepository;
import com.security.jwttest.util.SecurityUtil;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.Optional;

@Service
@AllArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public User signup(UserDTO userDTO){
        if(userRepository.findOneWithAuthoritiesByUsername(userDTO.getUsername()).orElse(null) != null){
            throw new RuntimeException("이미 가입되어 있는 유저 입니다.");
        }

        Authority authority = Authority.builder()
                .authorityName("ROLE_USER")
                .build(); // 회원가입이 가능할시 Authority entity 의 authorityName 을 ROLE_USER 로 세팅

        User user = User.builder()
                .username(userDTO.getUsername())
                .password(passwordEncoder.encode(userDTO.getPassword()))
                .nickname(userDTO.getNickname())
                .authorities(Collections.singleton(authority))
                .activated(true)
                .build();

        return userRepository.save(user);
    }
    @Transactional(readOnly = true)
    public Optional<User> getUserWithAuthorities(String username) { // 특정 유저의 정보와 권한 확인
        return userRepository.findOneWithAuthoritiesByUsername(username);
    }

    @Transactional(readOnly = true)
    public Optional<User> getMyUserWithAuthorities() { // 현재 SecurityContext 에 저장돼 있는 유저의 정보와 권한 확인
        return SecurityUtil.getCurrentUsername().flatMap(userRepository::findOneWithAuthoritiesByUsername);
    }
}
