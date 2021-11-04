package com.github.jwt.tokens.config;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.jwt.tokens.models.AccessKey;
import com.github.jwt.tokens.models.KeysStore;
import com.github.jwt.tokens.models.RefreshKey;
import com.github.jwt.tokens.utils.JwtKeyGenerator;
import com.github.jwt.tokens.utils.JwtTokenGenerator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Configuration
public class JwtTokensConfig {

    @Bean
    public JwtKeyGenerator jwtKeyGenerator() {
        return new JwtKeyGenerator();
    }

    @Bean
    @ConditionalOnExpression("${jwt.keys.store.enabled:true}")
    public Map<String, KeysStore>
    keysStore(@Value(value = "#{${keys.store}}") Object keysMainStore, ObjectMapper mapper) {
        return mapper.convertValue(keysMainStore, new TypeReference<>() {});
    }

    @Bean
    @ConditionalOnExpression("${jwt.keys.store.enabled:true}")
    public Map<String, AccessKey> accessKeyStore(Map<String, KeysStore> keysStore) {
        return keysStore.values().stream()
                .map(KeysStore::getAccessKey)
                .collect(Collectors.toMap(AccessKey::getId, Function.identity()));
    }

    @Bean
    @ConditionalOnExpression("${jwt.keys.store.enabled:true}")
    public Map<String, RefreshKey> refreshKeyStore(Map<String, KeysStore> keysStore) {
        return keysStore.values().stream()
                .map(KeysStore::getRefreshKey)
                .collect(Collectors.toMap(RefreshKey::getId, Function.identity()));
    }

    @Bean
    @ConditionalOnExpression("${jwt.keys.store.enabled:true}")
    public JwtTokenGenerator
    jwtTokenGenerator(Map<String, AccessKey> accessKeyStore, Map<String, RefreshKey> refreshKeyStore) {
        return new JwtTokenGenerator(accessKeyStore, refreshKeyStore);
    }

}
