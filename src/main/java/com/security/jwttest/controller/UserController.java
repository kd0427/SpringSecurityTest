package com.security.jwttest.controller;

import com.security.jwttest.dto.UserDTO;
import com.security.jwttest.entity.User;
import com.security.jwttest.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

import static org.springframework.http.ResponseEntity.badRequest;
import static org.springframework.http.ResponseEntity.notFound;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class UserController {
    private final UserService userService;

    @PostMapping("/signup")
    public ResponseEntity<User> signup(@Valid @RequestBody UserDTO userDTO){
        return  ResponseEntity.ok(userService.signup(userDTO)); //status 가 200ok
    }

    @GetMapping("/user")
    @PreAuthorize("hasAnyRole('USER','ADMIN')") // 이 메소드가 실행되기전에 권한이 있는지 검사하는 어노테이션
    public ResponseEntity<User> getMyUserInfo(){
        return ResponseEntity.ok(userService.getMyUserWithAuthorities().get());
    }

    @GetMapping("/user/{username}")
    @PreAuthorize("hasAnyRole('ADMIN')")
    public ResponseEntity<User> getUserInfo(@PathVariable String username){
        if(userService.getUserWithAuthorities(username).isPresent()){
            return ResponseEntity.ok(userService.getUserWithAuthorities(username).get());
        }
        return ResponseEntity.notFound().build();
    }
}
