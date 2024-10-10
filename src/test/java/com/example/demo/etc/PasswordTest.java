package com.example.demo.etc;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootTest
public class PasswordTest {

		@Autowired
		PasswordEncoder passwordEncoder;
		
		@Test
		void 암호화테스트() {
		
			// 평문
			String password = "1234";
			
			// 인코더를 사용하여 패스워드 암호화
			String enPw = passwordEncoder.encode(password);
			
			System.out.println("암호화된 패스워드: " + enPw);
			
			// 원본 문자열과 해시코드가 같은지 비교
			boolean isMatch = passwordEncoder.matches(password, enPw);
			
			System.out.println("결과 : " + isMatch);
			
		}
		
	
}
