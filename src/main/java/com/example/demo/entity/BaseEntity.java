package com.example.demo.entity;

import java.time.LocalDateTime;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import jakarta.persistence.EntityListeners;
import jakarta.persistence.MappedSuperclass;
import lombok.Getter;

@MappedSuperclass	// JPA가 엔티티를 스캔할 때 생략
@EntityListeners(value = {AuditingEntityListener.class})	// 이벤트를 감지하는 리스너 설정
@Getter


//시간을 관리하는 클래스
public class BaseEntity {

		@CreatedDate	// insert 시 현재시간을 저장
		LocalDateTime regDate;		// 등록일
		
		@LastModifiedDate	// update 시 현재시간을 저장
		LocalDateTime modDate;	// 수정일
		
}
