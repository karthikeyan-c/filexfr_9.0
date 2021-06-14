package com.kc.filexfr.Configuration;


import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.ArrayList;

@Configuration
public class SampleAuthenticationProvider implements AuthenticationProvider {
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();
        if (this.validateCredentials(username, password)) {
            return new UsernamePasswordAuthenticationToken(username, password, new ArrayList<>());
        }
        return null;
    }
    private boolean validateCredentials(String username, String password) {
        return username.equals("kc") && password.equals("kc");
    }
    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}

