package com.github.jwt.tokens.utils;

import com.github.jwt.tokens.exceptions.TokenNotFoundException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.util.StringUtils;

import java.util.UUID;

public class SubjectUtils {

    public static String getSubjAsString(String token) {
        if (!StringUtils.hasText(token)) throw new TokenNotFoundException();
        var signatureIndex = token.lastIndexOf('.');
        var nonSignedToken = token.substring(0, signatureIndex + 1);
        Claims body = Jwts.parserBuilder().build().parseClaimsJwt(nonSignedToken).getBody();
        return body.getSubject();
    }

    public static UUID getSubjAsUUID(String token) {
        return UUID.fromString(getSubjAsString(token));
    }

}
