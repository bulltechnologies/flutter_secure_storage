package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;

public interface StorageCipher {
    byte[] encrypt(byte[] input) throws Exception;

    byte[] decrypt(byte[] input) throws Exception;

    void deleteKey(Context context) throws Exception;

    default byte[] authenticateMigration(byte[] payload) throws Exception {
        throw new IllegalStateException("Cipher cannot authenticate ordinary migration metadata");
    }
}
