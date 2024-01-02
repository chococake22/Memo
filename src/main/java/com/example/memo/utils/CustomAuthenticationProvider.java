package com.example.memo.utils;

import com.example.memo.domain.UserVo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final MyUserDetailService myUserDetailService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        System.out.println("검사중");

        String username = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();

        UserVo userVo = (UserVo) myUserDetailService.loadUserByUsername(username);

        try {
            if (!passwordEncoder.matches("1234", password)) {
                throw new BadCredentialsException("비밀번호 틀렸다.");
            }
        } catch (CredentialsExpiredException e) {
            e.printStackTrace();
        }




        return new UsernamePasswordAuthenticationToken(userVo, null, userVo.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
