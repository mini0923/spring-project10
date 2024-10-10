package com.example.demo.service;

import org.springframework.data.domain.Page;

import com.example.demo.dto.MemberDTO;
import com.example.demo.entity.Member;

public interface MemberService {

		// 회원 목록 조회
		Page<MemberDTO> getList(int pageNumber);
		
		// 회원 등록
		boolean register(MemberDTO dto);
	
		// 회원 단건 조회
		MemberDTO read(String id);
		
		// 
		
		// 엔티티를 DTO로 변환하는 메소드
	
		default MemberDTO entityToDto(Member entity) {
			
				MemberDTO dto =  MemberDTO.builder()
																						.id(entity.getId())
																						.password(entity.getPassword())
																						.name(entity.getName())
																						.regDate(entity.getRegDate())
																						.modDate(entity.getModDate())
																						.role(entity.getRole())
																						.build();
				return dto;
			
		}
	
		// DTO를 엔티티로 변환하는 메소드
		default Member dtoToEntity(MemberDTO dto) {
			Member entity = Member.builder()
																			.id(dto.getId())
																			.password(dto.getPassword())
																			.name(dto.getName())
																			.role(dto.getRole())
																			.build();
			return entity;
		}
}


// 추상 메소드의 목적 : 자식들이 본인의 로직에 맞게 사용하는 기능
// 일반 메소드의 목적 : 공통 기능