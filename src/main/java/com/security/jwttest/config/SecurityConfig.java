package com.security.jwttest.config;
import com.security.jwttest.jwt.JwtAccessDeniedHandler;
import com.security.jwttest.jwt.JwtAuthenticationEntryPoint;
import com.security.jwttest.jwt.JwtSecurityConfig;
import com.security.jwttest.jwt.TokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
//MethodSecurity 는 말그대로 메소드 수준에서 권한을 제어할 수 있도록 해준다!
//특정 메소드마다 실행할 수 있는 역할을 제한할 수 있도록 해줌.
//단순히 허용, 거부 하는 것 보다 더 복잡한 규칙을 적용할 수 있음.
//GlobalMethodSecurity 사용을 활성화 하는 @EnableGlobalMethodSecurity 어노테이션을 추가
//
//prePostEnabled - Spring Security 의 @PreAuthorize, @PreFilter /@PostAuthorize, @PostFilter 어노테이션 활성화 여부
//securedEnabled - @Secured 어노테이션 활성화 여부
//jsr250Enabled - @RoleAllowed 어노테이션 사용 활성화 여부
//@PreAuthorize 는 해당 메서드가 호출되기 이전에 검사한다. 실제로 해당 메서드를 호출할 권한이 있는지를 확인!
//(PostAuthorize 는 메서드 호출 이후)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    public SecurityConfig(
            TokenProvider tokenProvider,
            JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
            JwtAccessDeniedHandler jwtAccessDeniedHandler
    ) {
        this.tokenProvider = tokenProvider;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {  // 비밀번호 암호화
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity web) {
        web
                .ignoring()
                .antMatchers(
                        "/h2-console/**"
                        , "/favicon.ico" // h2-console/하위 모든 요청과 파비콘은 모두 무시
                );
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()// 토큰을 사용하기 때문에 csrf 는 disable
                // CSRF
                // Cross site Request forgery 로 사이트간 위조 요청인데, 즉 정상적인 사용자가 의도치 않은 위조요청을 보내는 것을 의미한다.
                // CSRF protection 은 spring security 에서 default 로 설정된다.
                // 즉, protection 을 통해 GET 요청을 제외한 상태를 변화시킬 수 있는 POST, PUT, DELETE 요청으로부터 보호한다.

                //rest api 를 이용한 서버라면, session 기반 인증과는 다르게 stateless 하기 때문에
                // 서버에 인증정보를 보관하지 않는다. rest api 에서 client 는 권한이 필요한 요청을 하기 위해서는
                // 요청에 필요한 인증 정보를(OAuth2, jwt 토큰 등)을 포함시켜야 한다.
                // 따라서 서버에 인증정보를 저장하지 않기 때문에 굳이 불필요한 csrf 코드들을 작성할 필요가 없다.

                .exceptionHandling()// 예외처리 시에 만들었던 jwt 예외처리 핸들러 사용, 추가
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                .and()
                .headers()
                .frameOptions()
                .sameOrigin()

                .and()// 세션을 사용하지 않기 때문에 stateless 로 설정
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                .authorizeRequests()
                .antMatchers("/api/hello").permitAll()
                .antMatchers("/api/authenticate").permitAll()
                .antMatchers("/api/signup").permitAll()
                .anyRequest().authenticated()

                .and()
                .apply(new JwtSecurityConfig(tokenProvider));
                // JwtFilter 를 addFilterBefore 로 등록했던 JwtSecurityConfig 클래스도 적용
    }

}