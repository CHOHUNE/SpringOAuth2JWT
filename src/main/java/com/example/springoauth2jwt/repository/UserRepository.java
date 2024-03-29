package com.example.springoauth2jwt.repository;

import com.example.springoauth2jwt.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, Long> {



    boolean existsByUsername(String username);
    UserEntity findByUsername(String username);
}
