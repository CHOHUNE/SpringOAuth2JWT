package com.example.springoauth2jwt.dto;

import lombok.Data;
import org.springframework.security.oauth2.core.user.OAuth2User;

@Data
public class UserDTO {

    private String role;
    private String name;
    private String username;


}
