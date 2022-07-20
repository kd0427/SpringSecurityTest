package com.security.jwttest.repository;

import com.security.jwttest.entity.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;


public interface UserRepository extends JpaRepository<User,Long> {

    @EntityGraph(attributePaths = "authorities") // 쿼리가 수행될때 Lazy 조회가 아니고 Eager 조회로 가져온다.
    Optional<User> findOneWithAuthoritiesByUsername(String username);
    // username 을 기준으로 user 정보를 가져올때 권한 정보도 같이 가져오는
}
