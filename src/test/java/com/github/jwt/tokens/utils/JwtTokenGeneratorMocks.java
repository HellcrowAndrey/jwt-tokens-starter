package com.github.jwt.tokens.utils;

import com.github.jwt.tokens.entity.TokenInformation;
import com.github.jwt.tokens.models.AccessKey;
import com.github.jwt.tokens.models.RefreshKey;

import java.util.List;
import java.util.UUID;

public class JwtTokenGeneratorMocks {

     public static TokenInformation tokenInformation() {
         UUID uuid = UUID.randomUUID();
         var id = uuid.toString();
         return new TokenInformation() {
             @Override
             public UUID fetchUuIdAsId() {
                 return uuid;
             }

             @Override
             public String fetchId() {
                 return id;
             }

             @Override
             public List<String> fetchRoles() {
                 return List.of("ROLE_ADMIN");
             }

             @Override
             public String fetchName() {
                 return "Carlo Tester";
             }
         };
     }

     public static AccessKey accessKey() {
         return new AccessKey(
                "f6e33047-03fe-4bc8-8f3b-f36860cac22f",
                 23213,
                 "SAh0w03kK8JZh0iZdCSGxYUX5qjkRKuqK/rYStJBkGSyb2aWciUQOTJno0HpGucrmwURAftrU/Tqd12Dan+UbQ==",
                 "default",
                 "access_token"
         );
     }

     public static RefreshKey refreshKey() {
         return new RefreshKey(
                 "a5a06ffe-9422-46fc-b97c-41d5abf84a59",
                 12332,
                 "KSPqQ+Oa2tgjbozTBI/qIcLmPVHv58AI8RBttRBJzegGxZhfy4Opf8NOxjS73+Ok14yGOyLCwg+AfyDnAxujWQ==",
                 "refresh_token"
         );
     }

}
