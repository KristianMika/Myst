package mpc;


import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

//import javacardx.framework.math.BigNumber;

public class MPCApplet extends Applet {
	
	public MPCApplet() {
            ECPointBuilder.allocate();
            ECPointBase.allocate();
            CryptoOperations.allocate();
            DKG.allocate();
            Parameters.allocate();
            Bignat.allocate();
            Utils.allocate();
            CryptoObjects.allocate();
            
            CryptoObjects.KeyPair = new DKG();
            //CryptoObjects.EphimeralKey = new DKG();
            //CryptoObjects.EphimeralKey_next = new DKG();
            
            // Random card unique ID
            CryptoOperations.randomData.generateData(Parameters.cardIDLong, (short) 0, (short) Parameters.cardIDLong.length);
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new MPCApplet()
				.register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}



    public boolean select() {
        Reset();
        return true;
    }
    // ////////////////////////////////////////////////////////////////////////////////////
    public void process(APDU apdu) {
        byte[] buf = apdu.getBuffer();

        if (selectingApplet()) {
                return;
        }

        if (buf[ISO7816.OFFSET_CLA] == Consts.CLA_MPC) {


            // ////////////////
            // Process Input//
            // ///////////////
            byte[] apdubuf = apdu.getBuffer();
            short dataLen = apdu.setIncomingAndReceive(); // returns length of data field

            short p1 = (short) (apdubuf[ISO7816.OFFSET_P1] & 0x00FF);
            short p2 = (short) (apdubuf[ISO7816.OFFSET_P2] & 0x00FF);

            switch (buf[ISO7816.OFFSET_INS]) {

                // Card Management
                case Consts.INS_SETUP:
                        Setup(p1, p2);
                        break;
                case Consts.INS_STATUS:
                    getCardInfo(apdu);
                    break;
                case Consts.INS_RESET:
                        Reset();
                        break;
                    
                case Consts.INS_TESTRSAMULT:
                    TestRSAMult(apdu);
                    break;
                case Consts.INS_TESTECC:
                    TestNativeECC(apdu, dataLen);
                    break;                    
                case Consts.INS_SET_BACKDOORED_EXAMPLE:
                    // If p1 == 0x55, then set flag which will cause applet to behave as example backdoored one
                    if (p1 == (byte) 0x55) {
                        CryptoObjects.KeyPair.IS_BACKDOORED_EXAMPLE = true;
                        // Return the value of backdoored key
                        Util.arrayCopyNonAtomic(DKG.privbytes_backdoored, (short) 0, apdubuf, (short) 0, (short) DKG.privbytes_backdoored.length);
                        apdu.setOutgoingAndSend((short) 0, (short) DKG.privbytes_backdoored.length);
                    }
                    else {
                        CryptoObjects.KeyPair.IS_BACKDOORED_EXAMPLE = false;
                    }
                    break;

                // Key Generation
                case Consts.INS_KEYGEN_INIT:
                        CryptoObjects.KeyPair.Reset(Parameters.NUM_PLAYERS, Parameters.CARD_INDEX_THIS, true, false);
                        break;
                case Consts.INS_KEYGEN_RETRIEVE_HASH:
                        short len = CryptoObjects.KeyPair.GetHash(apdubuf, (short) 0);
                        apdu.setOutgoingAndSend((short) 0, len);
                        break;
                case Consts.INS_KEYGEN_STORE_HASH:
                        CryptoObjects.KeyPair.SetHash(p1, apdubuf, ISO7816.OFFSET_CDATA, dataLen);
                        break;
                case Consts.INS_KEYGEN_STORE_PUBKEY:
                        CryptoObjects.KeyPair.SetYs(p1, apdubuf, ISO7816.OFFSET_CDATA, dataLen);
                        break;
                case Consts.INS_KEYGEN_RETRIEVE_PUBKEY:
                        len = CryptoObjects.KeyPair.GetYi(apdubuf, (short) 0);
                        apdu.setOutgoingAndSend((short) 0, len);
                        break;
                case Consts.INS_KEYGEN_RETRIEVE_PRIVKEY:
                        len = CryptoObjects.KeyPair.Getxi(apdubuf, (short) 0);
                        apdu.setOutgoingAndSend((short) 0, len);
                        break;
                case Consts.INS_KEYGEN_RETRIEVE_AGG_PUBKEY:
                        len = CryptoObjects.KeyPair.GetY().getW(apdubuf, (short) 0);
                        apdu.setOutgoingAndSend((short) 0, len);                            
                        break;

                // Encrypt
                case Consts.INS_ENCRYPT:
                        len = CryptoOperations.Encrypt(apdubuf, ISO7816.OFFSET_CDATA, apdubuf, p1);
                        apdu.setOutgoingAndSend((short) 0, len);
                        break;

                // Decrypt
                case Consts.INS_DECRYPT:
                        len = CryptoOperations.DecryptShare(apdubuf, ISO7816.OFFSET_CDATA, apdubuf, p1);
                        apdu.setOutgoingAndSend((short) 0, len);
                        break;

                // Signing
                /*
                case Consts.INS_SIGN_INIT:
                        CryptoObjects.EphimeralKey.Reset(Parameters.NUM_PLAYERS, Parameters.CARD_INDEX_THIS, false, true);
                        //CryptoObjects.EphimeralKey_next.Reset(Parameters.NUM_PLAYERS, Parameters.CARD_INDEX_THIS); //Preloading
                        break;
                
                case Consts.INS_SIGN_RETRIEVE_HASH:
                        len = CryptoObjects.EphimeralKey.GetHash(apdubuf, (short) 0);
                        apdu.setOutgoingAndSend((short) 0, len);
                        break;
                case Consts.INS_SIGN_STORE_HASH:
                        CryptoObjects.EphimeralKey.SetHash(p1, apdubuf, ISO7816.OFFSET_CDATA, dataLen);
                        break;
                case Consts.INS_SIGN_STORE_RI:
                        CryptoObjects.EphimeralKey.SetYs(p1, apdubuf, ISO7816.OFFSET_CDATA, dataLen);
                        break;
                */
                /*case Consts.INS_SIGN_STORE_RI_N_HASH:
            	  		CryptoObjects.EphimeralKey.SetYs(p1, apdubuf, (short)ISO7816.OFFSET_CDATA, (short) Consts.SHARE_SIZE_CARRY_65);
            	  		CryptoObjects.EphimeralKey_next.SetHash(p1, apdubuf, (short)(ISO7816.OFFSET_CDATA + Consts.SHARE_SIZE_CARRY_65), (short) Consts.SHARE_SIZE_32);
                    	break;*/
                
                case Consts.INS_SIGN_RETRIEVE_RI:
                        //len = CryptoObjects.EphimeralKey.GetYi(apdubuf, (short) 0);
                		//Bignat zero = new Bignat((short)2, false);
                		//zero.one();
                		len = CryptoOperations.Gen_R_i(Utils.shortToByteArray(p1), CryptoObjects.secret_seed, apdubuf);
                		apdu.setOutgoingAndSend((short) 0, len);
                        break;
                
                /*case Consts.INS_SIGN_RETRIEVE_RI_N_HASH:
	                    len = CryptoObjects.EphimeralKey.GetYi(apdubuf, (short) 0);
	                    len = CryptoObjects.EphimeralKey_next.GetHash(apdubuf, Consts.SHARE_SIZE_CARRY_65);
	                    apdu.setOutgoingAndSend((short) 0, len);
	                    break;*/
                /*
                case Consts.BUGBUG_INS_SIGN_RETRIEVE_KI:
                        len = CryptoObjects.EphimeralKey.Getxi(apdubuf, (short) 0);
                        apdu.setOutgoingAndSend((short) 0, len);
                        break;
                case Consts.BUGBUG_INS_SIGN_RETRIEVE_R:
                        len = CryptoObjects.EphimeralKey.GetY().getW(apdubuf, (short) 0);
                        apdu.setOutgoingAndSend((short) 0, len);
                        break;
                */      
                case Consts.INS_SIGN:
                        CryptoObjects.Sign_counter.from_byte_array((short) 2, (short) 0, Utils.shortToByteArray((short) (p1 & 0xff)), (short) 0);
                        //CryptoObjects.Sign_counter.from_short((short) (p1 & 0xff)); // BUGBUG: this will not return same Bignat value as from_byte_array!!!

                        len = CryptoOperations.Sign(CryptoObjects.Sign_counter, apdubuf, (short)(ISO7816.OFFSET_CDATA), dataLen, apdubuf, (short) 0, p2);                        
                        //len = Util.arrayCopyNonAtomic(CryptoOperations.PRF(Utils.shortToBignat(p1), CryptoObjects.secret_seed), (short) 0, apdubuf, (short) 0, (short) 32);
                        apdu.setOutgoingAndSend((short) 0, len); //Send signature share 
                        break;
                        
                case Consts.INS_ADDPOINTS:
                    len = CryptoOperations.addPoint(apdubuf, ISO7816.OFFSET_CDATA, dataLen, apdubuf, (short) 0, p1);
                    apdu.setOutgoingAndSend((short) 0, len);
                    break;

                default:
                        // good practice: If you don't know the INStruction, say so:
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } else {
                ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }
        
    // ///////////////////////////////////////////////////////////////////
    // // Card Management functionality ////
    // ///////////////////////////////////////////////////////////////////
    void Setup(short p1, short p2) {
        Parameters.NUM_PLAYERS = p1;
        Parameters.CARD_INDEX_THIS = p2;

        CryptoObjects.KeyPair.Reset(Parameters.NUM_PLAYERS, Parameters.CARD_INDEX_THIS, true, false);
        //CryptoObjects.EphimeralKey.Reset(Parameters.NUM_PLAYERS, Parameters.CARD_INDEX_THIS, false, true);
       CryptoOperations.randomData.generateData(CryptoObjects.secret_seed, (short) 0, Consts.SHARE_SIZE_32);
       //CryptoObjects.secret_seed = JCSystem.makeTransientByteArray(Consts.SHARE_SIZE_32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
        
        Parameters.SETUP = true; // Ok, done
    }

    void Reset() {
        Parameters.Reset();
        CryptoObjects.Reset();
        // Restore proper value of modulo_Bn (was erased during the card's reset)
        CryptoOperations.modulo_Bn.from_byte_array((short) SecP256r1.r.length, (short) 0, SecP256r1.r, (short) 0);
        CryptoOperations.aBn.set_from_byte_array((short) (CryptoOperations.aBn.size() - (short) CryptoOperations.r_for_BigInteger.length), CryptoOperations.r_for_BigInteger, (short) 0, (short) CryptoOperations.r_for_BigInteger.length);
    }

    void getCardInfo(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        short offset = 0;

        buffer[offset] = Consts.TLV_TYPE_CARDUNIQUEDID;
        offset++;
        Util.setShort(buffer, offset, (short) Parameters.cardIDLong.length);
        offset += 2;
        Util.arrayCopyNonAtomic(Parameters.cardIDLong, (short) 0, buffer, offset, (short) Parameters.cardIDLong.length);
        offset += Parameters.cardIDLong.length;

        buffer[offset] = Consts.TLV_TYPE_KEYPAIR_STATE;
        offset++;
        Util.setShort(buffer, offset, (short) 2);
        offset += 2;
        Util.setShort(buffer, offset, CryptoObjects.KeyPair.getState());
        offset += 2;

        buffer[offset] = Consts.TLV_TYPE_EPHIMERAL_STATE;
        offset++;
        Util.setShort(buffer, offset, (short) 2);
        offset += 2;
        //Util.setShort(buffer, offset, CryptoObjects.EphimeralKey.getState());
        offset += 2;

        // Available memory
        buffer[offset] = Consts.TLV_TYPE_MEMORY;
        offset++;
        Util.setShort(buffer, offset, (short) 6);
        offset += 2;
        Util.setShort(buffer, offset, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT));
        offset += 2;
        Util.setShort(buffer, offset, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_RESET));
        offset += 2;
        Util.setShort(buffer, offset, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT));
        offset += 2;

        // Used compile-time switches
        buffer[offset] = Consts.TLV_TYPE_COMPILEFLAGS;
        offset++;
        Util.setShort(buffer, offset, (short) 4);
        offset += 2;
        Util.setShort(buffer, offset, Consts.MAX_N_PLAYERS);
        offset += 2;
        buffer[offset] = CryptoObjects.KeyPair.PLAYERS_IN_RAM ? (byte) 1 : (byte) 0;
        offset++;
        buffer[offset] = CryptoObjects.KeyPair.COMPUTE_Y_ONTHEFLY ? (byte) 1 : (byte) 0;
        offset++;
        
        // Git commit tag
        buffer[offset] = Consts.TLV_TYPE_GITCOMMIT;
        offset++;
        Util.setShort(buffer, offset, (short) 4);
        offset += 2; 
        Util.arrayCopyNonAtomic(Consts.GIT_COMMIT_MANUAL, (short) 0, buffer, offset, (short) Consts.GIT_COMMIT_MANUAL.length);
        offset += (short) Consts.GIT_COMMIT_MANUAL.length;
        
        // Flag about example demonstartion of beckdoored behavior
        buffer[offset] = Consts.TLV_TYPE_EXAMPLEBACKDOOR;
        offset++;
        Util.setShort(buffer, offset, (short) 1);
        offset += 2;
        buffer[offset] = CryptoObjects.KeyPair.IS_BACKDOORED_EXAMPLE ? (byte) 1 : (byte) 0;
        offset += 1;

        apdu.setOutgoingAndSend((short) 0, offset);
    }        
    
    /**
     * Set trusted hashes of public keys for all other cards that may eventually take part in protocol
     * Used to quickly verify provided player's public key during the protocol run
     * @param apdu 
     */
    void SetTrustedPubKeyHashes(APDU apdu) {
        // TODO
    }
    
    
     public final static byte[] xe_Bn_testInput1 = {
     (byte) 0x03, (byte) 0xBD, (byte) 0x28, (byte) 0x6B, (byte) 0x6A, (byte) 0x22, (byte) 0x1F, (byte) 0x1B, 
     (byte) 0xFC, (byte) 0x08, (byte) 0xC6, (byte) 0xC5, (byte) 0xB0, (byte) 0x3F, (byte) 0x0B, (byte) 0xEA, 
     (byte) 0x6C, (byte) 0x38, (byte) 0xBE, (byte) 0xBA, (byte) 0xCF, (byte) 0x20, (byte) 0x2A, (byte) 0xAA, 
     (byte) 0xDF, (byte) 0xAC, (byte) 0xA3, (byte) 0x70, (byte) 0x38, (byte) 0x32, (byte) 0xF8, (byte) 0xCC, 
     (byte) 0xE0, (byte) 0xA8, (byte) 0x70, (byte) 0x88, (byte) 0xE9, (byte) 0x17, (byte) 0x21, (byte) 0xA3, 
     (byte) 0x4C, (byte) 0x8D, (byte) 0x0B, (byte) 0x97, (byte) 0x11, (byte) 0x98, (byte) 0x02, (byte) 0x46, 
     (byte) 0x04, (byte) 0x56, (byte) 0x40, (byte) 0xA1, (byte) 0xAE, (byte) 0x34, (byte) 0xC1, (byte) 0xFB, 
     (byte) 0x7D, (byte) 0xB8, (byte) 0x45, (byte) 0x28, (byte) 0xC6, (byte) 0x1B, (byte) 0xC6, (byte) 0xD0};
         
    void TestNativeECC(APDU apdu, short dataLen) {
        byte[] buff = apdu.getBuffer();
        short pointSize = (short) (buff[(short) ISO7816.OFFSET_P2] & 0x00FF);
        
        if (buff[ISO7816.OFFSET_P1] == (byte) 0x01) {
            CryptoOperations.c1_EC.setW(buff, (short) ISO7816.OFFSET_CDATA, pointSize);
            CryptoOperations.c1_EC.AddPoint(buff, (short) (ISO7816.OFFSET_CDATA + pointSize), pointSize);
            short len = CryptoOperations.c1_EC.getW(buff, (short) 0);
            apdu.setOutgoingAndSend((short) 0, len);            
        }
        if (buff[ISO7816.OFFSET_P1] == (byte) 0x02) {
            CryptoOperations.c1_EC.setW(buff, (short) ISO7816.OFFSET_CDATA, pointSize);
            ECPointBase.disposable_priv.setS(buff, (short) (ISO7816.OFFSET_CDATA + pointSize), (short) (dataLen - pointSize));
            ECPointBase.ECMultiplHelper.init(ECPointBase.disposable_priv); // Set multiplier        
            short len = ECPointBase.ScalarMultiplication(CryptoOperations.c1_EC, ECPointBase.ECMultiplHelper, buff); 
            apdu.setOutgoingAndSend((short) 0, len);
        }   
    }
    
    void TestRSAMult(APDU apdu) {
        byte[] buff = apdu.getBuffer();
        CryptoOperations.e_Bn.from_byte_array((short) SecP256r1.r.length, (short) 0, SecP256r1.r, (short) 0);
        CryptoOperations.s_Bn.from_byte_array((short) SecP256r1.r.length, (short) 0, SecP256r1.r, (short) 0);
//        CryptoOperations.e_Bn.athousand();
//        CryptoOperations.s_Bn.twentyfive();
        
        if (buff[ISO7816.OFFSET_P1] == (byte) 0x01) {
            CryptoOperations.e_Bn.from_byte_array((short) SecP256r1.r.length, (short) 0, SecP256r1.r, (short) 0);
            CryptoOperations.s_Bn.from_byte_array((short) SecP256r1.r.length, (short) 0, SecP256r1.r, (short) 0);
            CryptoOperations.xe_Bn.mult(CryptoOperations.e_Bn, CryptoOperations.s_Bn);
        }
        if (buff[ISO7816.OFFSET_P1] == (byte) 0x02) {
            CryptoOperations.e_Bn.from_byte_array((short) SecP256r1.r.length, (short) 0, SecP256r1.r, (short) 0);
            CryptoOperations.s_Bn.from_byte_array((short) SecP256r1.r.length, (short) 0, SecP256r1.r, (short) 0);
            CryptoOperations.xe_Bn.multRSATrick(CryptoOperations.e_Bn, CryptoOperations.s_Bn);
        }
        if (buff[ISO7816.OFFSET_P1] == (byte) 0x03) {
            CryptoOperations.xe_Bn.from_byte_array((short) xe_Bn_testInput1.length, (short) 0, xe_Bn_testInput1, (short) 0);            
            CryptoOperations.xe_Bn.remainder_divide(CryptoOperations.modulo_Bn, null);
        }
        if (buff[ISO7816.OFFSET_P1] == (byte) 0x04) {
            CryptoOperations.xe_Bn.shiftBytes_right((short) 8);
        }
        
        if (buff[ISO7816.OFFSET_P1] == (byte) 0x05) {
            // -- begin - trick with RSA multiplication X/2^k
            // BUGBUG: set test input
            CryptoOperations.xe_Bn.from_byte_array((short) xe_Bn_testInput1.length, (short) 0, xe_Bn_testInput1, (short) 0);
            // xe_Bn % aBn = xe_Bn - ((xe_Bn * aBn) >> k) * aBn
            // (xe_Bn * aBn)
            //resBn1.mult(aBn, xe_Bn);
            CryptoOperations.resBn1.mult(CryptoOperations.aBn, CryptoOperations.xe_Bn);

            // ((n * a) >> k)
            CryptoOperations.resBn1.shiftBytes_right(CryptoOperations.SHIFT_BYTES_AAPROX); // 520 == 65*8

            // ((n * a) >> k) * r
            CryptoOperations.resBn2.from_byte_array(CryptoOperations.resBn2.size(), (short) 0, CryptoOperations.resBn1.as_byte_array(), (short) (CryptoOperations.resBn1.size() - CryptoOperations.resBn2.size()));

            CryptoOperations.resBn3.mult(CryptoOperations.modulo_Bn, CryptoOperations.resBn2);

            // n - ((n * a) >> k) * r
            byte[] result = CryptoOperations.xe_Bn.as_byte_array();
            byte[] inter = CryptoOperations.resBn3.as_byte_array();
            Bignat.subtract(result, (short) 0, (short) result.length, inter, (short) 0, (short) inter.length);        
        }
        
        if (buff[ISO7816.OFFSET_P1] == (byte) 0x06) {
            short offset = 0;

            CryptoOperations.xe_Bn.from_byte_array((short) xe_Bn_testInput1.length, (short) 0, xe_Bn_testInput1, (short) 0);
/*
            CryptoOperations.resBn1.zero();
            CryptoOperations.resBn1.mult(CryptoOperations.aBn, CryptoOperations.xe_Bn);
//            CryptoOperations.resBn1.mult(CryptoOperations.e_Bn, CryptoOperations.xe_Bn);
            Util.arrayCopyNonAtomic(CryptoOperations.resBn1.as_byte_array(), (short) 0, buff, offset, CryptoOperations.resBn1.size());
            offset += CryptoOperations.resBn1.size();
/*
            for (short i = 0; i < (short) 7; i++) {
                buff[offset] = (byte) i;
                offset++;
            }
            
            short xOffset;
            short yOffset;
            Bignat x = CryptoOperations.aBn;
            //Bignat x = CryptoOperations.xe_Bn;
            Util.arrayFillNonAtomic(Bignat.mult_resultArray2, (short) 0, (short) Bignat.mult_resultArray2.length, (byte) 0);
            xOffset = (short) (Bignat.mult_resultArray2.length - x.size());
            Util.arrayCopyNonAtomic(x.as_byte_array(), (short) 0, Bignat.mult_resultArray2, xOffset, x.size());
            Bignat.mult_cipher.doFinal(Bignat.mult_resultArray2, (byte) 0, (short) Bignat.mult_resultArray2.length, Bignat.mult_resultArray2, (short) 0);
//            Util.arrayCopyNonAtomic(Bignat.mult_resultArray2, (short) 0, buff, offset, (short) Bignat.mult_resultArray2.length);
//            offset += (short) Bignat.mult_resultArray2.length;

//            Bignat x = CryptoOperations.aBn;
            Bignat y = CryptoOperations.xe_Bn;
            // x+y
            Util.arrayFillNonAtomic(Bignat.mult_resultArray, (short) 0, (short) Bignat.mult_resultArray.length, (byte) 0);
            // We must copy bigger number first
            if (x.size() > y.size()) {
                // Copy x to the end of mult_resultArray
                xOffset = (short) (Bignat.mult_resultArray.length - x.size());
                Util.arrayCopyNonAtomic(x.as_byte_array(), (short) 0, Bignat.mult_resultArray, xOffset, x.size());
                if (Bignat.add(Bignat.mult_resultArray, xOffset, x.size(), y.as_byte_array(), (short) 0, y.size())) {
                    xOffset--;
                    Bignat.mult_resultArray[xOffset] = 0x01;
                }
            } else {
                // Copy x to the end of mult_resultArray
                yOffset = (short) (Bignat.mult_resultArray.length - y.size());
                Util.arrayCopyNonAtomic(y.as_byte_array(), (short) 0, Bignat.mult_resultArray, yOffset, y.size());
                if (Bignat.add(Bignat.mult_resultArray, yOffset, y.size(), x.as_byte_array(), (short) 0, x.size())) {
                    yOffset--;
                    Bignat.mult_resultArray[yOffset] = 0x01;
                }
            }
        //ISOException.throwIt((short) 0x666);

            // ((x+y)^2)
            Bignat.mult_cipher.doFinal(Bignat.mult_resultArray, (byte) 0, (short) Bignat.mult_resultArray.length, Bignat.mult_resultArray, (short) 0);            
            
            // ((x+y)^2) - x^2
            Bignat.subtract(Bignat.mult_resultArray, (short) 0, (short) Bignat.mult_resultArray.length, Bignat.mult_resultArray2, (short) 0, (short) Bignat.mult_resultArray2.length);
*/
            // xe_Bn^2
            Bignat y = CryptoOperations.aBn;
            //Bignat y = CryptoOperations.modulo_Bn;
            Util.arrayFillNonAtomic(Bignat.mult_resultArray2, (short) 0, (short) Bignat.mult_resultArray2.length, (byte) 0);
            short yOffset = (short) (Bignat.mult_resultArray2.length - y.size());
            Util.arrayCopyNonAtomic(y.as_byte_array(), (short) 0, Bignat.mult_resultArray2, yOffset, y.size());
            Bignat.mult_cipher.doFinal(Bignat.mult_resultArray2, (byte) 0, (short) Bignat.mult_resultArray2.length, Bignat.mult_resultArray2, (short) 0);
            
            //Bignat.subtract(Bignat.mult_resultArray, (short) 0, (short) Bignat.mult_resultArray.length, Bignat.mult_resultArray2, (short) 0, (short) Bignat.mult_resultArray2.length);
            
            
            Util.arrayCopyNonAtomic(Bignat.mult_resultArray2, (short) 0, buff, offset, (short) Bignat.mult_resultArray2.length);
            offset += (short) Bignat.mult_resultArray2.length;
            
/**/            
            
/*            
            CryptoOperations.xe_Bn.set_from_byte_array((short) 0, xe_Bn_testInput1, (short) 0, (short) xe_Bn_testInput1.length);
            CryptoOperations.resBn1.zero();
            CryptoOperations.resBn1.multRSATrick(CryptoOperations.aBn, CryptoOperations.xe_Bn);
            //CryptoOperations.resBn1.multRSATrick(CryptoOperations.e_Bn, CryptoOperations.xe_Bn);
            
            Util.arrayCopyNonAtomic(CryptoOperations.resBn1.as_byte_array(), (short) 0, buff, offset, CryptoOperations.resBn1.size());
            offset += CryptoOperations.resBn1.size();
/*            
            for (short i = 0; i < (short) 7; i++) {
                buff[offset] = (byte) 0;
                offset++;
            }            
*/
/*            
            CryptoOperations.xe_Bn.set_from_byte_array((short) 0, CryptoOperations.xe_Bn_testInput1, (short) 0, (short) CryptoOperations.xe_Bn_testInput1.length);
            CryptoOperations.resBn1.zero();
            CryptoOperations.resBn1.multRSATrick(CryptoOperations.xe_Bn, CryptoOperations.aBn);
            Util.arrayCopyNonAtomic(CryptoOperations.resBn1.as_byte_array(), (short) 0, buff, offset, CryptoOperations.resBn1.size());
            offset += CryptoOperations.resBn1.size();
/**/            
            
            apdu.setOutgoingAndSend((short) 0, offset);     
            return;
        }
/*        
        if (buff[ISO7816.OFFSET_P1] == (byte) 0x07) {
            // N % r = N_high32 | N_low32 | % r
            CryptoOperations.xe_Bn.from_byte_array((short) CryptoOperations.xe_Bn_testInput1.length, (short) 0, CryptoOperations.xe_Bn_testInput1, (short) 0);
            
            // 2^k mod r
            CryptoOperations.xe_Bn.remainder_divide(CryptoOperations.modulo_Bn, null);
            
            CryptoOperations.resBn1.mult(CryptoOperations.aBn, CryptoOperations.xe_Bn);

            short offset = 0;
            Util.arrayCopyNonAtomic(CryptoOperations.resBn1.as_byte_array(), (short) 0, buff, offset, CryptoOperations.resBn1.size());
            offset += CryptoOperations.resBn1.size();

            for (short i = 0; i < (short) 7; i++) {
                buff[offset] = (byte) 0;
                offset++;
            }

            CryptoOperations.xe_Bn.from_byte_array((short) CryptoOperations.xe_Bn_testInput1.length, (short) 0, CryptoOperations.xe_Bn_testInput1, (short) 0);
            CryptoOperations.resBn1.zero();
            CryptoOperations.resBn1.multRSATrick(CryptoOperations.aBn, CryptoOperations.xe_Bn);

            Util.arrayCopyNonAtomic(CryptoOperations.resBn1.as_byte_array(), (short) 0, buff, offset, CryptoOperations.resBn1.size());
            offset += CryptoOperations.resBn1.size();
            apdu.setOutgoingAndSend((short) 0, offset);
            return;
        }
*/        
        
        Util.arrayCopyNonAtomic(CryptoOperations.xe_Bn.as_byte_array(), (short) 0, buff, (short) 0, CryptoOperations.xe_Bn.size());
        apdu.setOutgoingAndSend((short) 0, CryptoOperations.xe_Bn.size());
    }
}
