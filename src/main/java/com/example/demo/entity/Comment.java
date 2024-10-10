package com.example.demo.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Entity
@Table(name = "tbl_comment")
@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Comment extends BaseEntity{

		@Id
		@GeneratedValue(strategy = GenerationType.IDENTITY)
		int commentNo;	// 댓글 번호
		
		@ManyToOne
		Board board;	// 게시물
	
		@Column(length = 1500)
		String content;	// 댓글 내용
		
		@ManyToOne
		Member writer;	// 작성자
		
}

// 회원가입을 하고 게시물을 작성한 후에 댓글을 달 수 있다.
// 회원은 여러개의 댓글을 작성할 수 있다.

