package org.example.aesalgorithm;

public class MySecretKey {
    private final byte[] key;

    public MySecretKey(byte[] key) throws Exception {
        if(key == null){
            throw new Exception("Secret key is null.");
        }
        if(key.length == 0){
            throw new Exception("Secret key is empty.");
        }
        this.key = key;
    }
}
