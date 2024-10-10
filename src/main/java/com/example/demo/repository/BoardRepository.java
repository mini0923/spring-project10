package com.example.demo.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.querydsl.QuerydslPredicateExecutor;
import org.springframework.data.repository.query.Param;

import com.example.demo.entity.Board;
import com.example.demo.entity.Member;

import jakarta.transaction.Transactional;

// Insert, Update, Delete 기능을 사용할 때 추가
// Commit 처리
@Transactional
public interface BoardRepository extends JpaRepository<Board, Integer>, QuerydslPredicateExecutor<Board>{

		// 특정 회원이 작성한 모든 게시물을 삭제하는 메소드
		@Modifying
		@Query("delete from Board where writer =:member")
		public void deleteWriter(@Param("member") Member member) ;
	
}

/* 
 * Repository 만드는 방법
 * 1. JpaRepository를 상속받는다.
 * 2. 제네릭 타입에 엔티티와 PK 타입을 쓴다.
 */