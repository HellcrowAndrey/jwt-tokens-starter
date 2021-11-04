package com.github.jwt.tokens.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.jwt.tokens.config.JwtTokensConfig;
import com.github.jwt.tokens.entity.TokenInformation;
import com.github.jwt.tokens.models.RefreshKey;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Date;
import java.util.UUID;

import static com.github.jwt.tokens.utils.JwtTokenGeneratorMocks.*;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(
        properties = {"jwt.keys.store.enabled=true"},
        classes = {JwtTokensConfig.class, ObjectMapper.class}
)
class JwtTokenGeneratorTest {

    @Autowired
    private JwtTokenGenerator tokenGenerator;

    @Test
    void givenTokenInformationAndAccessKey_whenAccessToken_thenReturnAccessToken() {
        assertNotNull(this.tokenGenerator.accessToken(tokenInformation(), accessKey()));
    }

    @Test
    void givenTokenInformationAndAccessKey_whenAccessToken_thenReturnNull() {
        assertNull(this.tokenGenerator.accessToken(null, accessKey()));
    }

    @Test
    void givenTokenInformationAndMetadata_whenRefreshToken_thenReturnRefreshToken() {
        assertNotNull(this.tokenGenerator.refreshToken(
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString(),
                new Date(),
                tokenInformation(),
                refreshKey()
        ));
    }

    @Test
    void givenTokenInformationAndMetadata_whenRefreshToken_thenReturnNull() {
        assertNull(this.tokenGenerator.refreshToken(
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString(),
                new Date(),
                null,
                refreshKey()
        ));
    }

    @Test
    void givenToken_whenFetchRefreshTokenFingerprint_thenReturnFingerprint() {
        var exp = UUID.randomUUID().toString();
        var token = this.tokenGenerator.refreshToken(
                exp,
                UUID.randomUUID().toString(),
                new Date(System.currentTimeMillis() + 555555),
                tokenInformation(),
                refreshKey()
        );
        assertEquals(exp, this.tokenGenerator.fetchRefreshTokenFingerprint(token));
    }

    @Test
    void givenToken_whenFetchRefreshTokenSessionId_thenReturnTokenSessionId() {
        var exp = UUID.randomUUID().toString();
        var token = this.tokenGenerator.refreshToken(
                UUID.randomUUID().toString(),
                exp,
                new Date(System.currentTimeMillis() + 555555),
                tokenInformation(),
                refreshKey()
        );
        assertEquals(exp, this.tokenGenerator.fetchRefreshTokenSessionId(token));
    }

    @Test
    void givenToken_whenFetchSubjectFromAccessToken_thenReturnSubject() {
        TokenInformation ti = tokenInformation();
        var token = this.tokenGenerator.accessToken(ti, accessKey());
        UUID act = this.tokenGenerator.fetchSubjectFromAccessToken(token);
        assertEquals(UUID.fromString(ti.fetchId()), act);
    }

    @Test
    void givenToken_whenFetchSubjectRefreshToken_thenReturnSubject() {
        TokenInformation ti = tokenInformation();
        var token = this.tokenGenerator.refreshToken(
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString(),
                new Date(System.currentTimeMillis() + 555555),
                ti,
                refreshKey()
        );
        UUID act = this.tokenGenerator.fetchSubjectRefreshToken(token);
        assertEquals(UUID.fromString(ti.fetchId()), act);
    }

    @Test
    void givenAccessToken_whenIsValidateToken_thenReturnTrue() {
        TokenInformation ti = tokenInformation();
        var token = this.tokenGenerator.accessToken(ti, accessKey());
        assertTrue(this.tokenGenerator.isAccessTokenValidate(token));
    }

    @Test
    void givenRefreshToken_whenIsValidateToken_thenReturnTrue() {
        var token = this.tokenGenerator.refreshToken(
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString(),
                new Date(System.currentTimeMillis() + 555555),
                tokenInformation(),
                refreshKey()
        );
        assertTrue(this.tokenGenerator.isRefreshTokenValidate(token));
    }

    @Test
    void givenRefreshToken_whenIsValidateToken_thenReturnFalse() {
        RefreshKey refreshKey = refreshKey();
        var token = this.tokenGenerator.refreshToken(
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString(),
                new Date(System.currentTimeMillis() - 555555),
                tokenInformation(),
                refreshKey
        );
        assertFalse(this.tokenGenerator.isTokenValidate(token, refreshKey.getKey()));
    }

    @Test
    void givenRefreshToken_whenValidateToken_thenReturnTrue() {
        RefreshKey refreshKey = refreshKey();
        var token = this.tokenGenerator.refreshToken(
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString(),
                new Date(System.currentTimeMillis() + 555555),
                tokenInformation(),
                refreshKey
        );
        assertTrue(this.tokenGenerator.validateToken(token, refreshKey.getKey()));
    }

    @Test
    void givenRefreshToken_whenValidateToken_thenThrowException() {
        RefreshKey refreshKey = refreshKey();
        var token = this.tokenGenerator.refreshToken(
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString(),
                new Date(System.currentTimeMillis() - 555555),
                tokenInformation(),
                refreshKey
        );
        assertThrows(JwtException.class, () ->
                this.tokenGenerator.validateToken(token, refreshKey.getKey()));
    }

}
