package com.example.memo.utils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;


// JWT를 이용한 인터셉터 구현
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtInterceptor implements HandlerInterceptor {

    private final JwtTokenProvider provider;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {

        String uri = request.getRequestURI();

        System.out.printf("uri : " + uri);

        // 액세스 토큰이 있으면 회원, 없으면 회원
        String accessToken = provider.getAccessToken(request);
        System.out.printf("accessToken : " + accessToken);

        String requestURI = request.getRequestURI();

        if (accessToken == null) {
            log.info("비회원 유저입니다 URI : {}", requestURI);
            System.out.printf("비회원" + requestURI);
            return true;
        } else {
            log.info("accessToken 존재");

            // 토큰 유효성 검사
            if (provider.validateToken(accessToken)) {
                log.info("유효한 토큰입니다. URI: {}", requestURI);
                System.out.println("유효 : " + requestURI);
                return true;
            } else {
                log.info("유효하지 않은 토큰입니다. URI: {}", requestURI);
                System.out.printf("유효하지 않음" + requestURI);
                return false;
            }
        }
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {
        HandlerInterceptor.super.postHandle(request, response, handler, modelAndView);
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        HandlerInterceptor.super.afterCompletion(request, response, handler, ex);
    }
}
