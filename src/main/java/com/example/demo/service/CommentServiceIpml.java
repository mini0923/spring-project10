package com.example.demo.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.demo.dto.CommentDTO;
import com.example.demo.entity.Board;
import com.example.demo.entity.Comment;
import com.example.demo.repository.CommentRepository;

@Service
public class CommentServiceIpml implements CommentService{

		@Autowired
		private CommentRepository repository;

			// 게시물 엔티티 생성
			@Override
			public List<CommentDTO> getListByBoardNo(int boardNo) {
				
				// 게시물 엔티티 생성
				Board board = Board.builder().no(boardNo).build();
				
				// 특정 게시물에 달린 댓글 목록 조회
				List<Comment> entityList = repository.findByBoard(board);
				
				List<CommentDTO> dtoList = new ArrayList<>();
				
				// 엔티티 리스트에서 요소를 하나씩 꺼내서 변환
				// 변환한 DTO를 새로운 리스트에 추가
				for(Comment comment : entityList) {
					CommentDTO dto = entityToDTO(comment);
					dtoList.add(dto);
				}
				
				return dtoList;	// 변환한 리스트를 반환
			}
		
			@Override
			public int register(CommentDTO dto) {
				
					// dto -> entity 
					Comment entity = dtoToEntity(dto);
					
					// 댓글 등록
					repository.save(entity);
					
					// 새로운 댓글 번호 반환
					return entity.getCommentNo();

			}
		
			@Override
			public boolean remove(int no) {

				// 해당 댓글이 있는지 확인
				Optional<Comment> comment = repository.findById(no);
				
				// 값이 있으면 삭제, 없으면 취소
				if(comment.isPresent()) {
					repository.deleteById(no);
					return true;
				} else {
					return false;
				}
			}

}
