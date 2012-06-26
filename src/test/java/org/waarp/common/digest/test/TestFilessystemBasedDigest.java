/**
   This file is part of Waarp Project.

   Copyright 2009, Frederic Bregier, and individual contributors by the @author
   tags. See the COPYRIGHT.txt in the distribution for a full listing of
   individual contributors.

   All Waarp Project is free software: you can redistribute it and/or 
   modify it under the terms of the GNU General Public License as published 
   by the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   Waarp is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with Waarp .  If not, see <http://www.gnu.org/licenses/>.
 */
package org.waarp.common.digest.test;

import java.io.File;
import java.io.IOException;

import org.waarp.common.digest.FilesystemBasedDigest;

/**
 * @author "Frederic Bregier"
 *
 */
public class TestFilessystemBasedDigest {

	/**
	 * Test function
	 *
	 * @param argv
	 *            with 2 arguments as filename to hash and full path to the
	 *            Native Library
	 * @throws IOException 
	 */
	public static void main(String argv[]) throws IOException {
	    if (argv.length < 1) {
	        FilesystemBasedDigest.useFastMd5 = false;
	        long start = System.currentTimeMillis();
	        for (int i = 0; i < 1000000; i++) {
	            FilesystemBasedDigest.passwdCrypt("Ceci est mon password!");
	        }
	        System.err.println("Final passwd crypted in "+(System.currentTimeMillis() - start)+"ms is: "+FilesystemBasedDigest.passwdCrypt("Ceci est mon password!"));
	        System.err
	                .println("Not enough argument: <full path to the filename to hash> ");
	        return;
	    }
	    File file = new File(argv[0]);
	    System.out.println("FileInterface: " + file.getAbsolutePath());
	    byte[] bmd5;
	    // one time for nothing
	    FilesystemBasedDigest.useFastMd5 = false;
	    long start = System.currentTimeMillis();
	    try {
	        bmd5 = FilesystemBasedDigest.getHashMd5Nio(file);
	    } catch (IOException e1) {
	        System.err
	                .println("Cannot compute " + FilesystemBasedDigest.DigestAlgo.MD5.name + " for " + argv[1]);
	        return;
	    }
	    long end = System.currentTimeMillis();
	    try {
	        Thread.sleep(6000);
	    } catch (InterruptedException e) {
	    }
	    System.out.println("Start testing");
	
	    // JVM Nio MD5
	    start = System.currentTimeMillis();
	    for (int i = 0; i < 100; i ++) {
	        try {
	            bmd5 = FilesystemBasedDigest.getHashMd5Nio(file);
	        } catch (IOException e1) {
	            System.err.println("Cannot compute " + FilesystemBasedDigest.DigestAlgo.MD5.name + " for " +
	                    argv[1]);
	            return;
	        }
	    }
	    end = System.currentTimeMillis();
	    System.out.println("Algo Nio JVM " + FilesystemBasedDigest.DigestAlgo.MD5.name + " is " + FilesystemBasedDigest.getHex(bmd5) +
	            "("+bmd5.length+")"+
	            " in " + (end - start) + " ms");
	    // Fast Nio MD5
	    FilesystemBasedDigest.useFastMd5 = true;
	    start = System.currentTimeMillis();
	    for (int i = 0; i < 100; i ++) {
	        try {
	            bmd5 = FilesystemBasedDigest.getHashMd5Nio(file);
	        } catch (IOException e1) {
	            System.err.println("Cannot compute " + FilesystemBasedDigest.DigestAlgo.MD5.name + " for " +
	                    argv[1]);
	            return;
	        }
	    }
	    end = System.currentTimeMillis();
	    System.out.println("Algo Nio Fast " + FilesystemBasedDigest.DigestAlgo.MD5.name + " is " + FilesystemBasedDigest.getHex(bmd5) +
	            "("+bmd5.length+")"+
	            " in " + (end - start) + " ms");
	
	    // JVM MD5
	    FilesystemBasedDigest.useFastMd5 = false;
	    start = System.currentTimeMillis();
	    for (int i = 0; i < 100; i ++) {
	        try {
	            bmd5 = FilesystemBasedDigest.getHashMd5(file);
	        } catch (IOException e1) {
	            System.err.println("Cannot compute " + FilesystemBasedDigest.DigestAlgo.MD5.name + " for " +
	                    argv[1]);
	            return;
	        }
	    }
	    end = System.currentTimeMillis();
	    System.out.println("Algo JVM " + FilesystemBasedDigest.DigestAlgo.MD5.name + " is " + FilesystemBasedDigest.getHex(bmd5) +
	            "("+bmd5.length+")"+
	            " in " + (end - start) + " ms");
	    // Fast MD5
	    FilesystemBasedDigest.useFastMd5 = true;
	    start = System.currentTimeMillis();
	    for (int i = 0; i < 100; i ++) {
	        try {
	            bmd5 = FilesystemBasedDigest.getHashMd5(file);
	        } catch (IOException e1) {
	            System.err.println("Cannot compute " + FilesystemBasedDigest.DigestAlgo.MD5.name + " for " +
	                    argv[1]);
	            return;
	        }
	    }
	    end = System.currentTimeMillis();
	    System.out.println("Algo Fast " + FilesystemBasedDigest.DigestAlgo.MD5.name + " is " + FilesystemBasedDigest.getHex(bmd5) +
	            "("+bmd5.length+")"+
	            " in " + (end - start) + " ms");
	
	    // JVM Nio SHA1
	    start = System.currentTimeMillis();
	    for (int i = 0; i < 100; i ++) {
	        try {
	            bmd5 = FilesystemBasedDigest.getHashSha1Nio(file);
	        } catch (IOException e1) {
	            System.err.println("Cannot compute " + FilesystemBasedDigest.DigestAlgo.SHA1.name + " for " +
	                    argv[1]);
	            return;
	        }
	    }
	    end = System.currentTimeMillis();
	    System.out.println("Algo Nio JVM " + FilesystemBasedDigest.DigestAlgo.SHA1.name + " is " + FilesystemBasedDigest.getHex(bmd5) +
	            "("+bmd5.length+")"+
	            " in " + (end - start) + " ms");
	    // JVM SHA1
	    start = System.currentTimeMillis();
	    for (int i = 0; i < 100; i ++) {
	        try {
	            bmd5 = FilesystemBasedDigest.getHashSha1(file);
	        } catch (IOException e1) {
	            System.err.println("Cannot compute " + FilesystemBasedDigest.DigestAlgo.SHA1.name + " for " +
	                    argv[1]);
	            return;
	        }
	    }
	    end = System.currentTimeMillis();
	    System.out.println("Algo JVM " + FilesystemBasedDigest.DigestAlgo.SHA1.name + " is " + FilesystemBasedDigest.getHex(bmd5) +
	            "("+bmd5.length+")"+
	            " in " + (end - start) + " ms");
	    // JVM Nio SHA256
	    start = System.currentTimeMillis();
	    for (int i = 0; i < 100; i ++) {
	        try {
	            bmd5 = FilesystemBasedDigest.getHash(file,true,FilesystemBasedDigest.DigestAlgo.SHA256);
	        } catch (IOException e1) {
	            System.err.println("Cannot compute " + FilesystemBasedDigest.DigestAlgo.SHA256.name + " for " +
	                    argv[1]);
	            return;
	        }
	    }
	    end = System.currentTimeMillis();
	    System.out.println("Algo Nio JVM " + FilesystemBasedDigest.DigestAlgo.SHA256.name + " is " + FilesystemBasedDigest.getHex(bmd5) +
	            "("+bmd5.length+")"+
	            " in " + (end - start) + " ms");
	    // JVM SHA256
	    start = System.currentTimeMillis();
	    for (int i = 0; i < 100; i ++) {
	        try {
	            bmd5 = FilesystemBasedDigest.getHash(file,false,FilesystemBasedDigest.DigestAlgo.SHA256);
	        } catch (IOException e1) {
	            System.err.println("Cannot compute " + FilesystemBasedDigest.DigestAlgo.SHA256.name + " for " +
	                    argv[1]);
	            return;
	        }
	    }
	    end = System.currentTimeMillis();
	    System.out.println("Algo JVM " + FilesystemBasedDigest.DigestAlgo.SHA256.name + " is " + FilesystemBasedDigest.getHex(bmd5) +
	            "("+bmd5.length+")"+
	            " in " + (end - start) + " ms");
	    // JVM Nio SHA512
	    start = System.currentTimeMillis();
	    for (int i = 0; i < 100; i ++) {
	        try {
	            bmd5 = FilesystemBasedDigest.getHash(file,true,FilesystemBasedDigest.DigestAlgo.SHA512);
	        } catch (IOException e1) {
	            System.err.println("Cannot compute " + FilesystemBasedDigest.DigestAlgo.SHA512.name + " for " +
	                    argv[1]);
	            return;
	        }
	    }
	    end = System.currentTimeMillis();
	    System.out.println("Algo Nio JVM " + FilesystemBasedDigest.DigestAlgo.SHA512.name + " is " + FilesystemBasedDigest.getHex(bmd5) +
	            "("+bmd5.length+")"+
	            " in " + (end - start) + " ms");
	    // JVM SHA512
	    start = System.currentTimeMillis();
	    for (int i = 0; i < 100; i ++) {
	        try {
	            bmd5 = FilesystemBasedDigest.getHash(file,false,FilesystemBasedDigest.DigestAlgo.SHA512);
	        } catch (IOException e1) {
	            System.err.println("Cannot compute " + FilesystemBasedDigest.DigestAlgo.SHA512.name + " for " +
	                    argv[1]);
	            return;
	        }
	    }
	    end = System.currentTimeMillis();
	    System.out.println("Algo JVM " + FilesystemBasedDigest.DigestAlgo.SHA512.name + " is " + FilesystemBasedDigest.getHex(bmd5) +
	            "("+bmd5.length+")"+
	            " in " + (end - start) + " ms");
	    // JVM Nio CRC32
	    start = System.currentTimeMillis();
	    for (int i = 0; i < 100; i ++) {
	        try {
	            bmd5 = FilesystemBasedDigest.getHash(file,true,FilesystemBasedDigest.DigestAlgo.CRC32);
	        } catch (IOException e1) {
	            System.err.println("Cannot compute " + FilesystemBasedDigest.DigestAlgo.CRC32.name + " for " +
	                    argv[1]);
	            return;
	        }
	    }
	    end = System.currentTimeMillis();
	    System.out.println("Algo Nio JVM " + FilesystemBasedDigest.DigestAlgo.CRC32.name + " is " + FilesystemBasedDigest.getHex(bmd5) +
	            "("+bmd5.length+")"+
	            " in " + (end - start) + " ms");
	    // JVM CRC32
	    start = System.currentTimeMillis();
	    for (int i = 0; i < 100; i ++) {
	        try {
	            bmd5 = FilesystemBasedDigest.getHash(file,false,FilesystemBasedDigest.DigestAlgo.CRC32);
	        } catch (IOException e1) {
	            System.err.println("Cannot compute " + FilesystemBasedDigest.DigestAlgo.CRC32.name + " for " +
	                    argv[1]);
	            return;
	        }
	    }
	    end = System.currentTimeMillis();
	    System.out.println("Algo JVM " + FilesystemBasedDigest.DigestAlgo.CRC32.name + " is " + FilesystemBasedDigest.getHex(bmd5) +
	            "("+bmd5.length+")"+
	            " in " + (end - start) + " ms");
	    // JVM Nio ADLER
	    start = System.currentTimeMillis();
	    for (int i = 0; i < 100; i ++) {
	        try {
	            bmd5 = FilesystemBasedDigest.getHash(file,true,FilesystemBasedDigest.DigestAlgo.ADLER32);
	        } catch (IOException e1) {
	            System.err.println("Cannot compute " + FilesystemBasedDigest.DigestAlgo.ADLER32.name + " for " +
	                    argv[1]);
	            return;
	        }
	    }
	    end = System.currentTimeMillis();
	    System.out.println("Algo Nio JVM " + FilesystemBasedDigest.DigestAlgo.ADLER32.name + " is " + FilesystemBasedDigest.getHex(bmd5) +
	            "("+bmd5.length+")"+
	            " in " + (end - start) + " ms");
	    // JVM ADLER
	    start = System.currentTimeMillis();
	    for (int i = 0; i < 100; i ++) {
	        try {
	            bmd5 = FilesystemBasedDigest.getHash(file,false,FilesystemBasedDigest.DigestAlgo.ADLER32);
	        } catch (IOException e1) {
	            System.err.println("Cannot compute " + FilesystemBasedDigest.DigestAlgo.ADLER32.name + " for " +
	                    argv[1]);
	            return;
	        }
	    }
	    end = System.currentTimeMillis();
	    System.out.println("Algo JVM " + FilesystemBasedDigest.DigestAlgo.ADLER32.name + " is " + FilesystemBasedDigest.getHex(bmd5) +
	            "("+bmd5.length+")"+
	            " in " + (end - start) + " ms");
	    // JVM MD2
	    start = System.currentTimeMillis();
	    for (int i = 0; i < 100; i ++) {
	        try {
	            bmd5 = FilesystemBasedDigest.getHash(file,false,FilesystemBasedDigest.DigestAlgo.MD2);
	        } catch (IOException e1) {
	            System.err.println("Cannot compute " + FilesystemBasedDigest.DigestAlgo.MD2.name + " for " +
	                    argv[1]);
	            return;
	        }
	    }
	    end = System.currentTimeMillis();
	    System.out.println("Algo JVM " + FilesystemBasedDigest.DigestAlgo.MD2.name + " is " + FilesystemBasedDigest.getHex(bmd5) +
	            "("+bmd5.length+")"+
	            " in " + (end - start) + " ms");
	    // JVM SHA-384
	    start = System.currentTimeMillis();
	    for (int i = 0; i < 100; i ++) {
	        try {
	            bmd5 = FilesystemBasedDigest.getHash(file,false,FilesystemBasedDigest.DigestAlgo.SHA384);
	        } catch (IOException e1) {
	            System.err.println("Cannot compute " + FilesystemBasedDigest.DigestAlgo.SHA384.name + " for " +
	                    argv[1]);
	            return;
	        }
	    }
	    end = System.currentTimeMillis();
	    System.out.println("Algo JVM " + FilesystemBasedDigest.DigestAlgo.SHA384.name + " is " + FilesystemBasedDigest.getHex(bmd5) +
	            "("+bmd5.length+")"+
	            " in " + (end - start) + " ms");
	}

}
