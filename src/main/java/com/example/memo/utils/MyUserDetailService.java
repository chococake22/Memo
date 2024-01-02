package com.example.memo.utils;

import com.example.memo.domain.UserVo;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class MyUserDetailService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        System.out.println(username);

        // 1. 회원 DB 조회 필요.
        // 2. 비밀번호 암호화

        UserVo userVo = UserVo.builder()
                .userId(username)
                .password("1234")
                .email("이메일")
                .phone("01012341234").build();

        return userVo;
    }
}
