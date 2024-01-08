package com.example.memo.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;

import java.io.IOException;

// AbstractAuthenticationProcessingFilter를 상속받아서 로그인 인증 필터를 재구성
public class LoginAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    protected LoginAuthenticationFilter(String defaultFilterProcessesUrl, AuthenticationManager authenticationManager) {
        super(defaultFilterProcessesUrl, authenticationManager);

        setSecurityContextRepository(new DelegatingSecurityContextRepository(
                new HttpSessionSecurityContextRepository(), new RequestAttributeSecurityContextRepository()
        ));
    }

    // 인증을 시도하는 메서드
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        String method = request.getMethod();

        if (!method.equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }

        // REST 방식으로 요청을 받기 위해서 적용함 -> JSON 데이터를 전달할 경우 inputStream에 Stream 형태로 값이 저장된다.
        // -> ObjectMapper를 이용해서 LoginRequestDto에 바인딩 -> 인증 토큰으로 만들어서 인증을 요청함.
        ServletInputStream inputStream = request.getInputStream();

        LoginRequestDto loginRequestDto = new ObjectMapper().readValue(inputStream, LoginRequestDto.class);

        // UsernamePasswordAuthenticationToken 인증 객체를 담는 역할
        return this.getAuthenticationManager().authenticate(new UsernamePasswordAuthenticationToken(
                loginRequestDto.userId,
                loginRequestDto.password
        ));
    }

    public record LoginRequestDto(
            String userId,
            String password
    ){}
}
