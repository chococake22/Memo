package com.example.memo.utils;


import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.util.Date;

@Component
@RequiredArgsConstructor
@Slf4j
// JWT 토큰 생성 및 검증하는 모듈
public class JwtTokenProvider {

    // secret key
    @Value("${spring.jwt.secret}")
    private static Key SECRET_KEY;

    @Value("${spring.jwt.validation_second}")
    public static long ACCESS_TOKEN_VALIDATION_SECOND;

    public final static String AUTHORIZATION_HEADER = "Authorization";

    // 액세스 토큰 생성
    public String createAccessToken(String userId, String name) {

        log.info("createAccessToken");

        // 토큰 만료 시간 설정(accessToken)
        Date now = new Date();
        Date expiration = new Date(now.getTime() + ACCESS_TOKEN_VALIDATION_SECOND);

        return Jwts.builder()
                .setSubject(userId)
                .claim("name", name)
                .setIssuedAt(now)
                .setExpiration(expiration)
                .signWith(SECRET_KEY)
                .compact();
    }

    // 토큰 유효성 검사
    public boolean validateToken(String token) {

        try {
            Jwts.parserBuilder().setSigningKey(SECRET_KEY).build().parseClaimsJws(token);

            return true;
        } catch (SignatureException e) {
            log.info("SignatureException ", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.info("ExpiredJwtException ", e.getMessage());
        } catch (IllegalArgumentException | MalformedJwtException e) {
            log.info("잘못된 토큰입니다.");
        }

        return false;
    }

    // 토큰에서 Id 추출하는 메서드
    public String getId(String token) {
        log.info("getId");

        return Jwts.parserBuilder().setSigningKey(SECRET_KEY).build().parseClaimsJws(token).getBody().get("name").toString();
    }

    // 액세스 토큰 가져오기
    public String getAccessToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);

        // 토큰이 있는 경우 반환
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    // 회원 또는 비회원 여부 확인
    // 리다이렉트로 전달
    public String determinedRedirectURI(HttpServletRequest request, String memberURI, String nonMemberURI) {

        String token = getAccessToken(request);

        if (token == null) {
            return nonMemberURI;
        } else {
            return memberURI;
        }
    }
}
