package com.example.springoauth2jwt.service;

import com.example.springoauth2jwt.entity.UserEntity;
import com.example.springoauth2jwt.dto.*;
import com.example.springoauth2jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;


    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);

        // super 키워드는 자식클래스에서 부모 클래스의 메서드나 생성자를 호출할 때 사용 된다.
        // 여기서는 super.loadUser(userRequest) 는 `CustomOAuth2UserService`가
        // DefaultOAuth2USerService 를 상속하고 있으므로, loadUser 메서드를 호출하는 것이다.
        // 결론 -> `super.loadUser(userRequest)는 `DefaultOAut2UserService 클래스의 loadUser 메서드를 호출해
        // OAuth2 사용자 정보를 가져오는 역할을 한다.

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        OAuth2Response oAuth2Response = null;
        if (registrationId.equals("naver")) {

            oAuth2Response = new NaverResponse(oAuth2User.getAttributes());

        } else if (registrationId.equals("google")) {

            oAuth2Response = new GoogleResponse(oAuth2User.getAttributes());
        }else{
            return null;
        }

        String username = oAuth2Response.getProvider() + " " + oAuth2Response.getProviderId();
        // 여기서 부터는 로그인 완료 이후의 추가 처리 로직 작성

        UserEntity existData = userRepository.findByUsername(username);

        if (existData == null) {
            UserEntity userEntity = new UserEntity();
            userEntity.setUsername(username);
            userEntity.setName(oAuth2Response.getName());
            userEntity.setEmail(oAuth2Response.getEmail());

            userRepository.save(userEntity);

            UserDTO userDTO = new UserDTO();

            userDTO.setUsername(username);
            userDTO.setName(oAuth2Response.getName());
            userDTO.setRole("ROLE_USER");

            return new CustomOAuth2User(userDTO);


        }else{

            existData.setUsername(username);
            existData.setEmail(oAuth2Response.getEmail());
            existData.setName(oAuth2Response.getName());

            userRepository.save(existData);

            UserDTO userDTO = new UserDTO();

            userDTO.setUsername(username);
            userDTO.setUsername(existData.getUsername());
            userDTO.setName(oAuth2Response.getName());
            userDTO.setRole(existData.getRole());

            return new CustomOAuth2User(userDTO);
        }
    }
}

// 해당 서비스는 SecurityConfig 에 있는 oAuth2Login에 등록 해야 한다.
// 기존에 있던 Customizer.withDefaults() 값을 지우고 본 서비스를 주입 하는 코드 작성 필요