package com.example.oauth.config;

import com.example.oauth.CustomAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//TODO authorizationServerConfigurer로 설정하는법, jwtDecoder 동작방식, client 식별자가 id, client_id 2개인데 각각 어느 상황에서 골라쓰면되는건지
//proxyBean false 이유 찾아보기
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

    @Autowired
    CustomAuthenticationProvider customAuthenticationProvider;
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE) // TODO 필터 선순위인데 이게 선순위가 되어야 하는 이유가 뭐지
    public SecurityFilterChain authsecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer<>();
        RequestMatcher endpointsMatcher = authorizationServerConfigurer
                .getEndpointsMatcher();

        authorizationServerConfigurer.authorizationEndpoint(
                authorizationEndpoint ->
                        authorizationEndpoint
                                .authenticationProvider(customAuthenticationProvider)
                                .authorizationResponseHandler((request, response, authentication) -> {
                                    OAuth2AuthorizationCodeRequestAuthenticationToken authentication1 = (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;
                                    System.out.println(authentication1);
                                    String redirectUri = authentication1.getRedirectUri();
                                    String authorizationCode = authentication1.getAuthorizationCode().getTokenValue();
                                    String state = null;
                                    if (StringUtils.hasText(authentication1.getState())) {
                                        state = authentication1.getState();
                                    }
                                    response.sendRedirect((redirectUri+"?code="+authorizationCode+"&state="+state));
                                })
                                .errorResponseHandler((request, response, exception) -> {
                                    System.out.println(exception.toString());
                                    response.sendError(HttpServletResponse.SC_BAD_REQUEST);
                                }));

        http
                .requestMatcher(endpointsMatcher)
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests.anyRequest().authenticated()
                )
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                .apply(authorizationServerConfigurer);
        // 진입점 지정
        http.exceptionHandling(exception -> exception.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));
        // jwt 복호화를 위해, 아랫줄 없으면 토큰 검증 못해서 anonymousUser됨
        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
        return http.build();
    }



}
