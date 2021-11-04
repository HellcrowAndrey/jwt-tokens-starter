package com.github.jwt.tokens.utils;

import com.github.jwt.tokens.config.JwtTokensConfig;
import com.github.jwt.tokens.models.KeysInfo;
import com.github.jwt.tokens.models.KeysStore;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static com.github.jwt.tokens.utils.JwtKeyGeneratorMocks.keysInfo;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(
        properties = {"jwt.keys.store.enabled=false"},
        classes = JwtTokensConfig.class
)
class JwtKeyGeneratorTest {

    @Autowired
    private JwtKeyGenerator instance;

    @Test
    void givenSignatureAlgorithm_whenGenerateKey_thenReturnSecretKey() {
       assertNotNull(this.instance.generateKey(SignatureAlgorithm.HS512));
    }

    @Test
    void givenKey_whenRestoreFromStr_thenReturnKey() {
        var key = this.instance.generateKey(SignatureAlgorithm.HS512);
        assertNotNull(this.instance.restoreFromStr(key));
    }

    @Test
    void givenKeysInfo_whenToKeysStore_thenReturnKeysStore() {
        KeysInfo data = keysInfo();
        KeysStore act = this.instance.toKeysStore(data, SignatureAlgorithm.HS512);
        assertNotNull(act);
        assertEquals(data.getPriority(), act.getPriority());
        assertNotNull(act.getAccessKey());
        assertNotNull(act.getAccessKey().getId());
        assertNotNull(act.getAccessKey().getKey());
        assertEquals(data.getAccessTokenExpireTime(), act.getAccessKey().getExpirationTime());
        assertNotNull(act.getRefreshKey());
        assertNotNull(act.getRefreshKey().getId());
        assertNotNull(act.getRefreshKey().getKey());
        assertEquals(data.getRefreshTokenExpireTime(), act.getRefreshKey().getExpirationTime());
    }

}