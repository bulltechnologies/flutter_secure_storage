package com.it_nomads.fluttersecurestorage.ciphers;

import java.security.Key;
import java.nio.charset.StandardCharsets;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

final class MigrationAuthentication {
    private MigrationAuthentication() {}
    static byte[] sign(Key root, byte[] payload) throws Exception {
        Mac derive = Mac.getInstance("HmacSHA256");
        derive.init(new SecretKeySpec(root.getEncoded(), "HmacSHA256"));
        byte[] metadataKey = derive.doFinal("index.fss.migration.metadata.v1".getBytes(StandardCharsets.UTF_8));
        Mac authenticate = Mac.getInstance("HmacSHA256");
        authenticate.init(new SecretKeySpec(metadataKey, "HmacSHA256"));
        return authenticate.doFinal(payload);
    }
}
