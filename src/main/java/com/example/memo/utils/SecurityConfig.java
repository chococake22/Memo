package com.example.memo.utils;

import jakarta.servlet.DispatcherType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

    private final JwtInterceptor jwtInterceptor;
    private final CustomUserDetailService myUserDetailService;

    private final CustomAuthenticationSuccessHandler successHandler;

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    private static final String[] AUTH_WHITELIST = {
            "/**",
    };

    // 여기서 전체적으로 설정을 해줌.
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        AuthenticationManagerBuilder sharedObject = http.getSharedObject(AuthenticationManagerBuilder.class);
        AuthenticationManager authenticationManager = sharedObject.build();

        http.authenticationManager(authenticationManager);

        return http
                // csrf 설정 해제
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(
                        authorize -> authorize
                                .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                                .requestMatchers("/api/**").permitAll()    // 해당하는 url 전부 접근 허용
                                .anyRequest().authenticated()

                ).formLogin(login -> login
                        .loginProcessingUrl("/api/login")
                        .usernameParameter("userId")
                        .passwordParameter("password")
//                        .successHandler(successHandler)  AbstractAuthenticationProcessingFilter를 구성해서 사용하면 successHandler 적용되지 않는다.
//                        .defaultSuccessUrl("/api/login-success", true)    // 기본적으로 로그인 성공시 '/'로 리다이렉트를 함(바로 직전 url에서 넘어오는데 이게 '/')
                )
                // 원래 default로 동작했던 UsernamePasswordAuthenticationFilter 대신에 AbstractAuthenticationProcessingFilter가 동작하도록 설정함.(필터 바꿔치핻)
                .addFilterAt(
                        this.abstractAuthenticationProcessingFilter(authenticationManager),
                        UsernamePasswordAuthenticationFilter.class)
                        .logout(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults())
                .build();
    }

    // cors 설정
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
        configuration.setAllowedHeaders(Arrays.asList("X-Requested-With", "Content-Type", "Authorization", "X-XSRF-token"));
        configuration.setAllowCredentials(false);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    // authentication 객체를 사용하여 사용자의 인증여부를 확인하는 역할.
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    // 직접 만든 로그인 필터(LoginAuthenticationFilter)를 등록해준다
    // /api/login를 요청하면 로그인 필터가 적용된다.
    public LoginAuthenticationFilter abstractAuthenticationProcessingFilter(
            final AuthenticationManager authenticationManager
    ) {

        return new LoginAuthenticationFilter(
                "/api/login",
                authenticationManager
        );
    }

}
