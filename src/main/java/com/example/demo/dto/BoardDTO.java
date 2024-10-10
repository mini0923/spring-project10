package com.example.demo.dto;

import java.time.LocalDateTime;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

// DTO : controller에서 view 로 데이터를 전달하는 용도
// Entity와 구조가 같을 때도 있고, 약간 다를 때도 있음 

@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class BoardDTO {

		int no;	// 게시물 번호
		String title;	// 제목
		String content;	// 내용
		String writer;	// 작성자
		LocalDateTime regDate;	// 등록일
		LocalDateTime modDate;	// 수정일
	
}
