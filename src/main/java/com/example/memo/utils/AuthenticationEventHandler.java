package com.example.memo.utils;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
@Slf4j
@EnableAsync
public class AuthenticationEventHandler {

    // 로그인 성공시 받는 이벤트 리스너
    @Async
    @EventListener // 특정 이벤트 발생시 그 이벤트에 대한 리스너를 구현할 수 있게 해주는 기능
    public void onSuccess(AuthenticationSuccessEvent event) {
        Authentication authentication = event.getAuthentication();
        log.info("Successful result: {}", authentication.getPrincipal());
    }

    // 로그인 실패시 받는 이벤트 리스너
    @Async
    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent event) {
        Exception e = event.getException();
        Authentication authentication = event.getAuthentication();
        log.warn("Unsuccessful result: {}", authentication, e);
    }
}
