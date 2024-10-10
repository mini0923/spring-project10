package com.example.demo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.example.demo.dto.CustomUser;
import com.example.demo.dto.MemberDTO;
import com.example.demo.service.MemberService;

// 커스텀 인증 클래스 생성
// 로그인 처리 서비스

@Service
public class UserDetailsServiceImpl implements UserDetailsService{

	@Autowired
	MemberService service;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
		System.out.println("login id : " + username );
		
		// 아이디로 회원 조회
		MemberDTO dto = service.read(username);
		
		// 회원이 있으면 로그인 성공, 없으면 실패
		if (dto != null) {
				// DTO -> 인증 객체로 변환
				return new CustomUser(dto);
		} else {
				// 에러 발생시키기
				throw new UsernameNotFoundException("");
		}
		
	}
	
	
		
}
