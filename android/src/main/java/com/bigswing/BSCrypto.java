package com.bigswing;

import android.util.Log;

import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import com.RNFetchBlob.RNFetchBlob;

public class BSCrypto {
    private static final String TAG = "RNFetchBlob";

    private static final String KEY_ALGORITHM = "AES";
    private static final byte CIPHER_STREAM_VERSION = 1;
    private static final String DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA1";

    /*
     * AES/CTR/NoPadding is a useful fast algorithm that doesn't change the 
     * length of the data w/padding.
     * AES/GCM would be excellent and would offer corruption-manipulation, but
     * this would be more challenging to integrate since Android does not ship
     * with it by default.
     */
    private static final String CIPHER_ALGORITHM = "AES/CTR/NoPadding";

    /*
     * 128-bit IV (based on key)
     */
    private static final int IV_LENGTH = 128 / 8;

    /*
     * 128-bit keys should be sufficient, though could be tweaked to 192 or 256
     */
    private static final int KEY_LENGTH = 128 / 8;

    /*
     * Number of iterations - longer = more secure but slower to convert PW -> key
     */
    private static final int ITERATION_COUNT = 1000;

    /* SecureRandom - somewhat expensive to construct, but thread-safe */
    private static final SecureRandom RNG = new SecureRandom();
    /* 8 random bytes for salt is 'pretty good' */
    private static final int SALT_LENGTH = 8;

    public interface SaltSource {
        byte[] getSalt();
    }

    private static class ApplicationSaltSource implements SaltSource {
        @Override
        public byte[] getSalt() {
            // Log.d(TAG, "app salt: " + Arrays.toString(RNFetchBlob.appSalt));
            return RNFetchBlob.appSalt;
        }
    }

    private final SaltSource saltSource;

    public BSCrypto() {
        saltSource = new ApplicationSaltSource();
    }

    public byte[] generateKey(String password) throws GeneralSecurityException {
        byte[] salt = saltSource.getSalt();
        char[] passwordChars = password.toCharArray();
        final int keyBitLength = KEY_LENGTH * 8;
        KeySpec keySpec = new PBEKeySpec(passwordChars, salt, ITERATION_COUNT, keyBitLength);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(DERIVATION_ALGORITHM);
        return keyFactory.generateSecret(keySpec).getEncoded();
    }

    /**
     * Construct a new encryption stream.
     * Be sure to close this out. If you don't want the underlying stream closed, but data flushed,
     * use a stream filter like "CloseShield*" from commons.io.
     * @param output stream to write output data to
     * @param key to use for encryption
     * @return wrapped output stream to operate on
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public OutputStream createEncryptor(OutputStream output, byte[] key) throws IOException, GeneralSecurityException {
        /* Write out version field - useful to add in case you want to change cipher later */
        output.write(CIPHER_STREAM_VERSION);

        /* Create IV - random for every encrypted form */
        byte[] iv = new byte[16];
        RNG.nextBytes(iv);
        output.write(iv);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        SecretKey keySpec = new SecretKeySpec(key, KEY_ALGORITHM);
        AlgorithmParameterSpec params = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, params);
        CipherOutputStream cipherStream = new CipherOutputStream(output, cipher);
        return cipherStream;
    }
}