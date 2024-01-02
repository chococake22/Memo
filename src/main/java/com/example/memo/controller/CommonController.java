package com.example.memo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class CommonController {

    @PostMapping("/login")
    public String login() {

        System.out.println("로그인 api 호출");

        return "success";
    }

    @GetMapping("/login-success")
    public String loginSuccess() {
        return "로그인 성공했습니다";
    }
}
