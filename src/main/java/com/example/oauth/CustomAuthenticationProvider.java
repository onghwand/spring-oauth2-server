package com.example.oauth;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {
    private final RegisteredClientRepository registeredClientRepository; // 클라이언트 db 접근
    private final OAuth2AuthorizationService oAuth2AuthorizationService; // 토큰들 저장된 객체 접근
    private final OAuth2AuthorizationConsentService oAuth2AuthorizationConsentService; // 사용자 동의 객체 저장 및 조회

    // 1. 인증이 안되어 있으면 로그인 폼 띄우고 로그인 시킨 다음에 다시 OAuth2AuthorizationCodeRequestAuthenticationProvider -> authenticate
    // 2. 인증이 된 상태지만 동의가 필요한 상태이면 동의 폼 띄우고 체크받은 다음 다시 OAuth2AuthorizationCodeRequestAuthenticationProvider -> authenticate
    // 3. 인증&동의 다 된 상태면 토큰(OAuth2AuthorizationCodeRequestAuthenticationToken) 발행 -> 토큰에는 인가 코드, state, redirectUrl 포함
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 요청 파라미터를 받아서 토큰화한 것
        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication
                = (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;

        // authenticationProvider 생성
        OAuth2AuthorizationCodeRequestAuthenticationProvider authenticationProvider
                = new OAuth2AuthorizationCodeRequestAuthenticationProvider(registeredClientRepository, oAuth2AuthorizationService, oAuth2AuthorizationConsentService);
        // authenticate
        OAuth2AuthorizationCodeRequestAuthenticationToken authenticate
                = (OAuth2AuthorizationCodeRequestAuthenticationToken) authenticationProvider.authenticate(authorizationCodeRequestAuthentication);

        Authentication principal = (Authentication) authorizationCodeRequestAuthentication.getPrincipal();
        System.out.println("principal = " + principal);

        return authenticate;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeRequestAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
