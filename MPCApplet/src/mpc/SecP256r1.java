/* Copyright (c) 2013 Yubico AB 
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package mpc;

import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;

public class SecP256r1 {
	
	public final static short KEY_LENGTH = 256;
	
	public final static byte[] p = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, (byte) 0xff,
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };

	public final static byte[] p_2 = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, (byte) 0xff,
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xfd };
	
	
	public final static byte[] a = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, (byte) 0xff,
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xfc 
	};

	public final static byte[] b = { 0x5a, (byte) 0xc6, 0x35, (byte) 0xd8, (byte) 0xaa, 0x3a,
		(byte) 0x93, (byte) 0xe7, (byte) 0xb3, (byte) 0xeb, (byte) 0xbd, 0x55, 0x76, (byte) 0x98,
		(byte) 0x86, (byte) 0xbc, 0x65, 0x1d, 0x06, (byte) 0xb0, (byte) 0xcc, 0x53, (byte) 0xb0,
		(byte) 0xf6, 0x3b, (byte) 0xce, 0x3c, 0x3e, 0x27, (byte) 0xd2, 0x60, 0x4b };

	public final static byte[] G = { 0x04, 0x6b, 0x17, (byte) 0xd1, (byte) 0xf2, (byte) 0xe1, 0x2c,
		0x42, 0x47, (byte) 0xf8, (byte) 0xbc, (byte) 0xe6, (byte) 0xe5, 0x63, (byte) 0xa4, 0x40,
		(byte) 0xf2, 0x77, 0x03, 0x7d, (byte) 0x81, 0x2d, (byte) 0xeb, 0x33, (byte) 0xa0, (byte) 0xf4,
		(byte) 0xa1, 0x39, 0x45, (byte) 0xd8, (byte) 0x98, (byte) 0xc2, (byte) 0x96, 0x4f, (byte) 0xe3,
		0x42, (byte) 0xe2, (byte) 0xfe, 0x1a, 0x7f, (byte) 0x9b, (byte) 0x8e, (byte) 0xe7, (byte) 0xeb,
		0x4a, 0x7c, 0x0f, (byte) 0x9e, 0x16, 0x2b, (byte) 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e,
		(byte) 0xce, (byte) 0xcb, (byte) 0xb6, 0x40, 0x68, 0x37, (byte) 0xbf, 0x51, (byte) 0xf5 };

	public final static byte[] _G = { (byte) 0x04, (byte) 0x6B, (byte) 0x17, (byte) 0xD1, (byte) 0xF2,
		(byte) 0xE1, (byte) 0x2C, (byte) 0x42, (byte) 0x47, (byte) 0xF8, (byte) 0xBC, (byte) 0xE6,
		(byte) 0xE5, (byte) 0x63, (byte) 0xA4, (byte) 0x40, (byte) 0xF2, (byte) 0x77, (byte) 0x03,
		(byte) 0x7D, (byte) 0x81, (byte) 0x2D, (byte) 0xEB, (byte) 0x33, (byte) 0xA0, (byte) 0xF4,
		(byte) 0xA1, (byte) 0x39, (byte) 0x45, (byte) 0xD8, (byte) 0x98, (byte) 0xC2, (byte) 0x96,
		(byte) 0xB0, (byte) 0x1C, (byte) 0xBD, (byte) 0x1C, (byte) 0x01, (byte) 0xE5, (byte) 0x80,
		(byte) 0x65, (byte) 0x71, (byte) 0x18, (byte) 0x14, (byte) 0xB5, (byte) 0x83, (byte) 0xF0, 
		(byte) 0x61, (byte) 0xE9, (byte) 0xD4, (byte) 0x31, (byte) 0xCC, (byte) 0xA9, (byte) 0x94,
		(byte) 0xCE, (byte) 0xA1, (byte) 0x31, (byte) 0x34, (byte) 0x49, (byte) 0xBF, (byte) 0x97,
		(byte) 0xC8, (byte) 0x40, (byte) 0xAE, (byte) 0x0A};
	
	
	
	
	public final static byte[] r = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, 0x00, 0x00, 0x00,
		0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		(byte) 0xff, (byte) 0xbc, (byte) 0xe6, (byte) 0xfa, (byte) 0xad, (byte) 0xa7, 0x17, (byte) 0x9e,
		(byte) 0x84, (byte) 0xf3, (byte) 0xb9, (byte) 0xca, (byte) 0xc2, (byte) 0xfc, 0x63, 0x25, 0x51 };

	
	public static ECPrivateKey setPrivParams(ECPrivateKey privKey) {
		privKey.setFieldFP(p, (short) 0, (short) p.length);
		privKey.setA(a, (short) 0, (short) a.length);
		privKey.setB(b, (short) 0, (short) b.length);
		privKey.setG(G, (short) 0, (short) G.length);
		privKey.setR(r, (short) 0, (short) r.length);

		return privKey;
	}

	
	public static ECPublicKey setPubParams(ECPublicKey pubKey) {
		pubKey.setFieldFP(p, (short) 0, (short) p.length);
		pubKey.setA(a, (short) 0, (short) a.length);
		pubKey.setB(b, (short) 0, (short) b.length);
		pubKey.setG(G, (short) 0, (short) G.length);
		pubKey.setR(r, (short) 0, (short) r.length);

		return pubKey;
	}
	
	
	
	public static KeyPair newKeyPair() {
		//byte[] privbytes = {(byte)0xB3, (byte)0x46, (byte)0x67, (byte)0x55, (byte)0x18, (byte)0x08, (byte)0x46, (byte)0x23, (byte)0xBC, (byte)0x11, (byte)0x1C, (byte)0xC5, (byte)0x3F, (byte)0xF6, (byte)0x15, (byte)0xB1, (byte)0x52, (byte)0xA3, (byte)0xF6, (byte)0xD1, (byte)0x58, (byte)0x52, (byte)0x78, (byte)0x37, (byte)0x0F, (byte)0xA1, (byte)0xBA, (byte)0x0E, (byte)0xA1, (byte)0x60, (byte)0x23, (byte)0x7E};
		
		KeyPair key = new KeyPair(KeyPair.ALG_EC_FP, KEY_LENGTH);

		ECPrivateKey privKey = (ECPrivateKey) key.getPrivate();
		//privKey.setS(privbytes, (short)0, (short)32);
		ECPublicKey pubKey = (ECPublicKey) key.getPublic();

		privKey.setFieldFP(p, (short) 0, (short) p.length);
		privKey.setA(a, (short) 0, (short) a.length);
		privKey.setB(b, (short) 0, (short) b.length);
		privKey.setG(G, (short) 0, (short) G.length);
		privKey.setR(r, (short) 0, (short) r.length);

		pubKey.setFieldFP(p, (short) 0, (short) p.length);
		pubKey.setA(a, (short) 0, (short) a.length);
		pubKey.setB(b, (short) 0, (short) b.length);
		pubKey.setG(G, (short) 0, (short) G.length);
		pubKey.setR(r, (short) 0, (short) r.length);
		
		return key;
	}
}