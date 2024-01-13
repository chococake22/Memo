package com.example.memo.controller.controller;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
public class LoginController {

    @GetMapping("/")
    public void redirectSuccessLogin(HttpServletResponse response) throws IOException {

        System.out.println("로그인 api 호출");

        response.sendRedirect("/api/login-success");
    }
}
