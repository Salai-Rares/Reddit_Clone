package com.example.Reddit_clone.service;

import com.example.Reddit_clone.exceptions.SpringRedditException;
import com.example.Reddit_clone.model.RefreshToken;
import com.example.Reddit_clone.repository.RefreshTokenRepository;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.time.Instant;
import java.util.UUID;

@Service
@AllArgsConstructor
@Transactional
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;
    public RefreshToken generateRefreshToken(){
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setCreatedDate(Instant.now());

        return refreshTokenRepository.save(refreshToken);
    }

   public void validateRefreshToken(String token){
        refreshTokenRepository.findByToken(token).orElseThrow(()->new SpringRedditException("Invalid refresh token"));
    }
    public void deleteRefreshToken(String token){
        refreshTokenRepository.deleteByToken(token);
    }
}
