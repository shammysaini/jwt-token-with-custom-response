package com.security;

import com.repo.AdminRepo;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final AdminRepo adminRepo;
    private final JwtUtils jwtUtils;
    private final AuthenticationManager authenticationManager;

    public AuthService(AdminRepo adminRepo, JwtUtils jwtUtils, AuthenticationManager authenticationManager) {
        this.adminRepo = adminRepo;
        this.jwtUtils = jwtUtils;
        this.authenticationManager = authenticationManager;
    }

    public Authentication authenticate(String email, String password) {
       return authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, password));

    }
}