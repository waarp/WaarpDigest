/**
 * This file is part of Waarp Project.
 * 
 * Copyright 2009, Frederic Bregier, and individual contributors by the @author tags. See the
 * COPYRIGHT.txt in the distribution for a full listing of individual contributors.
 * 
 * All Waarp Project is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 * 
 * Waarp is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even
 * the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with Waarp . If not, see
 * <http://www.gnu.org/licenses/>.
 */
package org.waarp.common.digest.test;

import java.io.File;
import java.io.IOException;

import org.waarp.common.digest.MD5;

/**
 * @author "Frederic Bregier"
 * 
 */
public class TestMD5 {

	/**
	 * Test function
	 * 
	 * @param argv
	 *            with 2 arguments as filename to hash and full path to the Native Library
	 */
	public static void main(String argv[]) {
		long start = System.currentTimeMillis();
		if (argv.length < 1) {
			// Only passwdCrypt test
			for (int i = 0; i < 1000000; i++) {
				MD5.passwdCrypt("Ceci est mon password!");
			}
			System.err.println("Final passwd crypted in " + (System.currentTimeMillis() - start)
					+ "ms is: " + MD5.passwdCrypt("Ceci est mon password!"));
			System.err
					.println("Not enough argument: <full path to the filename to hash> [<full path to the native library>]");
			return;
		}
		boolean nativeLib = false;
		File file = new File(argv[0]);
		byte[] bmd5;
		try {
			// By recompiling using the first: NIO support, the second: standard
			// support
			bmd5 = MD5.getHashNio(file);
			// bmd5 = getHash(file);
		} catch (IOException e1) {
			bmd5 = null;
		}
		if (bmd5 != null) {
			if (nativeLib) {
				System.out.println("FileInterface MD5 is " + MD5.asHex(bmd5) +
						" using Native Library in " +
						(System.currentTimeMillis() - start) + " ms");
			} else {
				System.out.println("FileInterface MD5 is " + MD5.asHex(bmd5) +
						" using Java version in " +
						(System.currentTimeMillis() - start) + " ms");
			}
		} else {
			System.err.println("Cannot compute md5 for " + argv[1]);
		}
	}

}
