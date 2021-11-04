package com.github.jwt.tokens.utils;

import com.github.jwt.tokens.entity.TokenInformation;
import com.github.jwt.tokens.models.AccessKey;
import com.github.jwt.tokens.models.RefreshKey;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class JwtTokenGenerator {

    private static final Logger log = LoggerFactory.getLogger(JwtTokenGenerator.class);

    private static final String AUTHORITIES = "AUTHORITIES";

    private final Map<String, AccessKey> accessKeyStore;

    private final Map<String, RefreshKey> refreshKeyStore;

    public JwtTokenGenerator(Map<String, AccessKey> accessKeyStore, Map<String, RefreshKey> refreshKeyStore) {
        this.accessKeyStore = accessKeyStore;
        this.refreshKeyStore = refreshKeyStore;
    }

    public String accessToken(TokenInformation ti, AccessKey key) {
        return accessToken(ti, key.getExpirationTime(), key.getId(), key.getKey());
    }

    public String accessToken(TokenInformation ti, int expireTime, String keyId, String key) {
        if (Objects.nonNull(ti)) {
            var now = new Date();
            var date = new Date(now.getTime() + expireTime);
            List<String> authorities = ti.fetchRoles();
            return Jwts.builder()
                    .setSubject(ti.fetchId())
                    .claim(AUTHORITIES, authorities)
                    .claim("subjectName", ti.fetchName())
                    .setHeaderParam(JwsHeader.KEY_ID, keyId)
                    .setIssuedAt(new Date())
                    .setExpiration(date)
                    .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(key)), SignatureAlgorithm.HS512)
                    .compact();
        }
        return null;
    }

    public String refreshToken(String fingerprint, String sessionId, Date expire, TokenInformation ti, RefreshKey key) {
        return refreshToken(fingerprint, sessionId, expire, ti, key.getId(), key.getKey());
    }

    public String refreshToken(String fingerprint, String sessionId, Date expire, TokenInformation ti, String keyId, String key) {
        if (Objects.nonNull(ti)) {
            return Jwts.builder()
                    .setSubject(ti.fetchId())
                    .claim("sessionId", sessionId)
                    .claim("fingerprint", fingerprint)
                    .claim("subjectName", ti.fetchName())
                    .setHeaderParam(JwsHeader.KEY_ID, keyId)
                    .setIssuedAt(new Date())
                    .setExpiration(expire)
                    .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(key)), SignatureAlgorithm.HS512)
                    .compact();
        }
        return null;
    }

    public UUID fetchSubjectFromAccessToken(String token) {
        String keyId = getKeyId(token);
        return fetchSubject(token, this.accessKeyStore.get(keyId).getKey());
    }

    public UUID fetchSubjectRefreshToken(String token) {
        String keyId = getKeyId(token);
        return fetchSubject(token, this.refreshKeyStore.get(keyId).getKey());
    }

    public UUID fetchSubject(String token, String key) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return UUID.fromString(claims.getSubject());
    }

    public String fetchRefreshTokenFingerprint(String token) {
        return fetchFingerprint(token, this.refreshKeyStore.get(getKeyId(token)).getKey());
    }

    public String fetchRefreshTokenSessionId(String token) {
        return fetchSessionId(token, this.refreshKeyStore.get(getKeyId(token)).getKey());
    }

    public String fetchFingerprint(String token, String key) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.get("fingerprint", String.class);
    }

    public String fetchSessionId(String token, String key) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.get("sessionId", String.class);
    }

    public boolean isAccessTokenValidate(String token) {
        return isTokenValidate(token, this.accessKeyStore.get(getKeyId(token)).getKey());
    }

    public boolean isRefreshTokenValidate(String token) {
        return isTokenValidate(token, this.refreshKeyStore.get(getKeyId(token)).getKey());
    }

    public boolean validateToken(String token, String key) throws SignatureException, MalformedJwtException,
            ExpiredJwtException, UnsupportedJwtException, IllegalArgumentException {
        Jwts.parserBuilder().setSigningKey(key)
                .build()
                .parseClaimsJws(token);
        return true;
    }

    public boolean isTokenValidate(String token, String key) {
        try {
            Jwts.parserBuilder().setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (JwtException e) {
            log.error("Enter: {}", e.getMessage());
        }
        return false;
    }

    public String getKeyId(String token) {
        var signatureIndex = token.lastIndexOf('.');
        var nonSignedToken = token.substring(0, signatureIndex + 1);
        Header<?> h = Jwts.parserBuilder().build().parseClaimsJwt(nonSignedToken).getHeader();
        return String.valueOf(h.get(JwsHeader.KEY_ID));
    }

}
