package com.example.demo.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.demo.dto.MemberDTO;
import com.example.demo.entity.Member;
import com.example.demo.repository.MemberRepository;

@Service
public class MemberServiceImpl implements MemberService {
		
	@Autowired
	MemberRepository repository;
	
	// 인코더 필드 선언
	@Autowired
	PasswordEncoder passwordEncoder;

	@Override
	public Page<MemberDTO> getList(int pageNumber) {
		
		// 전달받은 페이지번호를 인덱스로 변경
		int pageIndex = (pageNumber == 0) ? 0 : pageNumber - 1;
		
		
		// 페이징 조건 만들기
		// 정렬 조건 만들기 : 등록일 기준으로 내림차순 정렬
		Pageable pageable = PageRequest.of(pageIndex, 10, Sort.by("regDate").descending());
		
		// 회원 목록 조회
		Page<Member> entityPage = repository.findAll(pageable);
		
		// 엔티티 리스트를 DTO 리스트로 변환
		Page<MemberDTO> dtoPage = entityPage.map(entity -> entityToDto(entity));
		
		return dtoPage;
	}


	@Override
	public boolean register(MemberDTO dto) {
		
			// 회원 정보에서 아이디 꺼내기
			String id = dto.getId();
			
			// 아이디 중복 여부를 확인하고, 회원 등록을 진행
			MemberDTO getDto = read(id);
			
			// 해당 아이디가 사용중이라면 등록 취소
			if(getDto != null) {
				System.out.println("사용중인 아이디입니다.");
				return false;
			}  else {
				Member entity = dtoToEntity(dto);
				
				// 인코더로 패스워드를 암호화 한 후 업데이트
				String enPw = passwordEncoder.encode(entity.getPassword());
				entity.setPassword(enPw);
				
				repository.save(entity);
				return true;
			}
	}


	@Override
	public MemberDTO read(String id) {
		
		Optional<Member> result = repository.findById(id);
		
		if(result.isPresent()) {
			Member member = result.get();
			return entityToDto(member);
		}
		
		return null;
	}

}
