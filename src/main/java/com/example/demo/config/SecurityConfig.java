package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration				// 스프링 설정 클래스
@EnableWebSecurity	// 보안 설정
public class SecurityConfig {

		// 로그인 인증 처리를 위한 필터 체인
		@Bean
		public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			
			http.authorizeHttpRequests()
						.requestMatchers("/register").permitAll()
						.requestMatchers("/assets/*", "/css/*", "/js/*").permitAll()
						.requestMatchers("/").authenticated()
						.requestMatchers("/board/*").hasAnyRole("ADMIN","USER")
						.requestMatchers("/comment/*").hasAnyRole("ADMIN","USER")
						.requestMatchers("/member/*").hasRole("ADMIN");
			
			// 로그인 폼 화면 설정
//			http.formLogin();
			
			// 로그아웃 설정
			http.logout();
			
			// csrf 설정 (get 외에 post, put, delete 허용) 
			http.csrf().disable();
			
	        //커스텀 로그인 페이지와 처리 주소 설정 
	        http.formLogin( form -> 
	        					form.loginPage("/customlogin")
	        					.loginProcessingUrl("/login")
	                            .permitAll()
	                            .successHandler((request, response, authentication) -> {
	                                response.sendRedirect("/"); // 로그인 성공 시 리다이렉트
	                            })
	                      );
	        
			return http.build();
		}
	
	
		// 회원 가입 시 사용자 패스워드를 암호화하는데 사용할 인코더
		// BCrypt : 암호화 알고리즘 종류 (단방향) 
		@Bean	// 빈을 생성하여 컨테이너에 저장
		public PasswordEncoder passwordEncoder() {
			
			return new BCryptPasswordEncoder();
		}
	
}
