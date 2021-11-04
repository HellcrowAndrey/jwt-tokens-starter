package com.github.jwt.tokens.entity;

import java.util.List;
import java.util.UUID;

public interface TokenInformation {

    UUID fetchUuIdAsId();

    String fetchId();

    List<String> fetchRoles();

    String fetchName();

}
