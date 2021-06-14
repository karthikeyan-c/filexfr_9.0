package com.kc.filexfr.Configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

//@Configuration
public class MyConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        /*http.authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .httpBasic();

        http
                .csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());*/

        http
               /* .formLogin()
                .loginPage("/login")
                //.failureUrl("/loginError")
                .loginProcessingUrl("/authenticate")
                .defaultSuccessUrl("/")
                .and()
                .logout().clearAuthentication(true).invalidateHttpSession(true).deleteCookies("JSESSIONID")
                .logoutSuccessUrl("/login")
                .and()
                */
                .csrf()
                .disable()
                //.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        ; //HERE !  Defaults XSRF-TOKEN as cookie name and X-XSRF-TOKEN as header name*/
    }
}
