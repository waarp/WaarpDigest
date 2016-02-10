package org.waarp.common.digest;

import static org.junit.Assert.*;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import org.junit.Test;
import org.waarp.common.digest.FilesystemBasedDigest.DigestAlgo;

public class FilesystemBasedDigestTest {
    private static final String TESTPHRASE = "This is a phrase to test";
    private static final byte[] TESTPHRASEBYTES = TESTPHRASE.getBytes();

    @Test
    public void testGetHashByteBufDigestAlgo() {

        try {
            for (int j = 0; j < 2; j++) {
                for (DigestAlgo algo : DigestAlgo.values()) {
                    long start = System.currentTimeMillis();
                    byte[] bmd5 = null;
                    for (int i = 0; i < 100000; i++) {
                        FilesystemBasedDigest.setUseFastMd5(false);
                        FilesystemBasedDigest digest = new FilesystemBasedDigest(algo);
                        digest.Update(TESTPHRASEBYTES, 0, TESTPHRASEBYTES.length);
                        bmd5 = digest.Final();
                        String hex = FilesystemBasedDigest.getHex(bmd5);
                        assertTrue(algo + " Hex Not Equals", FilesystemBasedDigest.digestEquals(hex, bmd5));
                        FilesystemBasedDigest.setUseFastMd5(true);
                        FilesystemBasedDigest digest2 = new FilesystemBasedDigest(algo);
                        digest2.Update(TESTPHRASEBYTES, 0, TESTPHRASEBYTES.length);
                        byte[] bmd52 = digest2.Final();
                        String hex2 = FilesystemBasedDigest.getHex(bmd52);
                        assertTrue(algo + " Hex Not Equals", FilesystemBasedDigest.digestEquals(hex2, bmd52));
                        assertTrue(algo + " FastMD5 vs MD5 Not Equals", FilesystemBasedDigest.digestEquals(bmd52, bmd5));
                        FilesystemBasedDigest.setUseFastMd5(false);
                        ByteBuf buf = Unpooled.wrappedBuffer(TESTPHRASEBYTES);
                        byte[] bmd53 = FilesystemBasedDigest.getHash(buf, algo);
                        buf.release();
                        String hex3 = FilesystemBasedDigest.getHex(bmd53);
                        assertTrue(algo + " Hex Not Equals", FilesystemBasedDigest.digestEquals(hex3, bmd53));
                        assertTrue(algo + " Through ByteBuf vs Direct Not Equals",
                                FilesystemBasedDigest.digestEquals(bmd53, bmd5));
                        assertTrue(algo + " FromHex Not Equals",
                                FilesystemBasedDigest.digestEquals(bmd53, FilesystemBasedDigest.getFromHex(hex3)));
                    }
                    long end = System.currentTimeMillis();
                    System.out.println("Algo: " + algo + " KeyLength: " + bmd5.length + " Time: " + (end - start));
                }
            }
        } catch (NoSuchAlgorithmException e) {
            fail(e.getMessage());
        } catch (IOException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testPasswdCryptString() {
        for (int j = 0; j < 2; j++) {
            long start = System.currentTimeMillis();
            byte[] bmd5 = null;
            for (int i = 0; i < 100000; i++) {
                FilesystemBasedDigest.setUseFastMd5(false);
                String crypt = FilesystemBasedDigest.passwdCrypt(TESTPHRASE);
                byte[] bcrypt = FilesystemBasedDigest.passwdCrypt(TESTPHRASEBYTES);
                bmd5 = bcrypt;
                assertTrue("Password Hex Not Equals", FilesystemBasedDigest.digestEquals(crypt, bcrypt));
                assertTrue("Password Not Equals", FilesystemBasedDigest.equalPasswd(TESTPHRASEBYTES, bcrypt));
                assertTrue("Password Not Equals", FilesystemBasedDigest.equalPasswd(TESTPHRASE, crypt));
            }
            long end = System.currentTimeMillis();
            System.out.println("Algo: CRYPT KeyLength: " + bmd5.length + " Time: " + (end - start));
        }
    }

}
