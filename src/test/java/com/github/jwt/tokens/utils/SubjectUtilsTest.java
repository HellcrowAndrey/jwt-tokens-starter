package com.github.jwt.tokens.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.jwt.tokens.config.JwtTokensConfig;
import com.github.jwt.tokens.entity.TokenInformation;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.UUID;

import static com.github.jwt.tokens.utils.JwtTokenGeneratorMocks.accessKey;
import static com.github.jwt.tokens.utils.JwtTokenGeneratorMocks.tokenInformation;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(
        properties = {"jwt.keys.store.enabled=true"},
        classes = {JwtTokensConfig.class, ObjectMapper.class}
)
class SubjectUtilsTest {

    @Autowired
    private JwtTokenGenerator tokenGenerator;

    @Test
    void givenToken_whenGetSubjectAsString_thenReturnSubjectAsString() {
        TokenInformation data = tokenInformation();
        String token = this.tokenGenerator.accessToken(data, accessKey());
        String act = SubjectUtils.getSubjAsString(token);
        assertEquals(data.fetchId(), act);
    }

    @Test
    void givenToken_whenGetSubjectAsUUID_thenReturnSubjectAsUUID() {
        TokenInformation data = tokenInformation();
        String token = this.tokenGenerator.accessToken(data, accessKey());
        UUID act = SubjectUtils.getSubjAsUUID(token);
        assertEquals(data.fetchUuIdAsId(), act);
    }

}