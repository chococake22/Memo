package com.example.memo.controller;

import com.example.memo.domain.UserVo;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class CommonController {

    @PostMapping("/login")
    public String login(@RequestBody UserVo userVo) {

        System.out.println(userVo.getUsername());
        System.out.println(userVo.getPassword());

        System.out.println("로그인 api 호출");

        return "success";
    }

    @GetMapping("/login-success")
    public String loginSuccess() {
        return "로그인 성공했습니다";
    }
}
