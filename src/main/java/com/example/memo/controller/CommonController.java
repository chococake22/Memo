package com.example.memo.controller;

import com.example.memo.domain.UserVo;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class CommonController {

    @GetMapping("/login-success")
    public String success(@AuthenticationPrincipal UserVo userVo) {

        System.out.println("--------- 로그인 성공 후 리다이렉트하기 ---------");
        System.out.println(userVo.getUserId());
        System.out.println(userVo.getPassword());
        System.out.println(userVo.getPhone());
        System.out.println(userVo.getEmail());

        return "도착했다";
    }
}
