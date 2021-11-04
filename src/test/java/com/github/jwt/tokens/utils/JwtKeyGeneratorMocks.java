package com.github.jwt.tokens.utils;

import com.github.jwt.tokens.models.KeysInfo;

public class JwtKeyGeneratorMocks {

    public static KeysInfo keysInfo() {
        return new KeysInfo(
                "ROLE_ADMIN",
                10,
                23213,
                12332
        );
    }

}
