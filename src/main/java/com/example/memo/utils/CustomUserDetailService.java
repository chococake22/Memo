package com.example.memo.utils;

import com.example.memo.domain.UserVo;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class CustomUserDetailService implements UserDetailsService {

    private Map<String, User> roles = new HashMap<>();

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        return UserVo.builder()
                .userId(username)
                .password("1234")
                .phone("01012341234")
                .email("apple12@gmail.com").build();
    }

    private List<GrantedAuthority> getAuthority(String role) {
        return Collections.singletonList(new SimpleGrantedAuthority(role));
    }
}
