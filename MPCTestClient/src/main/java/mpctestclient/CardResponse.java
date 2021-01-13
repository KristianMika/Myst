package mpctestclient;

import mpc.Consts;

import javax.smartcardio.ResponseAPDU;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;


/**
 * This class represents an APDU response from a card.
 * Its main purpose is to parse an incoming APDU, verify SW and signature and resolve error codes
 * to the corresponding exceptions if an error occurred.
 *
 * @author Kristian Mika
 */
public class CardResponse {

    private byte[] raw_data;
    private byte[] data;
    private byte[] signature;
    private byte[] nonce;
    private final short quorumI;


    public CardResponse(ResponseAPDU responseAPDU, byte[] nonce, short quorumI) throws MPCException {
        this(responseAPDU, quorumI);
        this.nonce = nonce;
    }

    public CardResponse(ResponseAPDU responseAPDU, short quorumI) throws MPCException {
        this.checkSW(responseAPDU);
        this.parseResponse(responseAPDU.getBytes());
        this.quorumI = quorumI;
    }


    public byte[] getRaw_data() {
        return raw_data;
    }

    public byte[] getData() {
        return data;
    }

    public byte[] getSignature() {
        return signature;
    }

    public byte[] getNonce() {
        return nonce;
    }

    public short getQuorumI() {
        return quorumI;
    }

    /**
     * Parses a response apdu and sets the data and the signature byte arrays.
     * Data = 2B data length | xB Data | 2B sigLen | yB signature
     *
     * @param data    response APDU
     */
    private void parseResponse(byte[] data) {

        short dataLen = Util.getShort(data, Consts.PACKET_PARAMS_APDU_OUT_DATALENGTH_OFFSET);
        short sigLen = Util.getShort(data, Consts.SHORT_SIZE + dataLen);

        this.signature = Arrays.copyOfRange(data, Consts.SHORT_SIZE + dataLen + Consts.SHORT_SIZE,
                Consts.SHORT_SIZE + dataLen + Consts.SHORT_SIZE + sigLen);


        this.raw_data = Arrays.copyOfRange(data, 0, Consts.SHORT_SIZE + dataLen);
        this.data = Arrays.copyOfRange(data, Consts.SHORT_SIZE, Consts.SHORT_SIZE + dataLen);

    }

    /**
     * Verifies an APDU signature.
     * SVer_CardPbuKey(QuorumI, nonce, apdu bytes)
     *
     * @param pubkey    public key used for signature verification
     * @throws GeneralSecurityException
     * @throws InvalidCardSignatureException in case of invalid signature
     */
    void verifySignature(PublicKey pubkey) throws GeneralSecurityException, InvalidCardSignatureException {
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initVerify(pubkey);
        ecdsa.update(Util.shortToByteArray(quorumI));
        if (this.nonce != null) {
            ecdsa.update(nonce);
        }
        ecdsa.update(raw_data);
        if (!(ecdsa.verify(signature))) {
            throw new InvalidCardSignatureException();
        }
    }

    /**
     * Checks SW of a response APDU.
     * @param response responseAPDU
     * @throws MPCException if sw != Consts.SW_SUCCESS
     */
    private void checkSW(ResponseAPDU response) throws MPCException {
        if (response.getSW() != (Consts.SW_SUCCESS & 0xffff)) {
            System.err.printf("Received error status: %02X.\n", response.getSW());
            handleReturnCode((short) response.getSW());
        }
    }

    /**
     * Resolves a return code to the corresponding exception.
     *
     * @param retCode Code returned from a card.
     * @throws MPCException
     */
    static void handleReturnCode(short retCode) throws MPCException {
        switch (retCode) {

            case Consts.SW_SUCCESS:
                return;

            case Consts.SW_DUPLICATE_HOST_ID:
                throw new DuplicateHostIdException();

            case Consts.SW_HOSTNOTALLOWED:
                throw new HostNotAllowedException();

            case Consts.SW_INVALID_PACKET_SIGNATURE:
                throw new InvalidHostSignatureException();

            case Consts.SW_INVALID_HOST_ID:
                throw new InvalidHostIdException();

            case Consts.SW_FUNCTINNOTALLOWED:
                throw new FunctionNotAllowedException();
            case Consts.SW_APPLET_LOCKED:
                throw new AppletLockedException();

            default:
                throw new MPCException(String.format("0x%02X",retCode));
        }
    }

}
