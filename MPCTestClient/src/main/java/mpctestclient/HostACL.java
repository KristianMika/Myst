package mpctestclient;


import org.bouncycastle.math.ec.ECPoint;

/**
 * Class that stores host's public key and permissions for submitting queries
 */
public class HostACL {

    // User's access privileges (can be customised)
    public final static short ACL_FULL_PRIVILEGES                = (short) 0xffff;
    public final static short ACL_KEY_GENERATION                 = (short) 0x0001; // 0000 0000  0000 0001
    public final static short ACL_QUORUM_MANAGEMENT              = (short) 0x0002; // 0000 0000  0000 0010
    public final static short ACL_ENCRYPT                        = (short) 0x0004; // 0000 0000  0000 0100 (probably useless, encryption can be done by anyone who has the aggregated pubkey)
    public final static short ACL_DECRYPT                        = (short) 0x0008; // 0000 0000  0000 1000
    public final static short ACL_SIGN                           = (short) 0x0010; // 0000 0000  0001 0000

    private final byte[] id;
    private final short permissions;


    public HostACL(byte[] id, short permissions) {
        this.id = id;
        this.permissions = permissions;
    }

    public short getPermissions() {
        return permissions;
    }

    public byte[] getId() {
        return id;
    }

    public void VerifyCallerAuthorization(short requestedFnc) throws MPCException {
        VerifyCallerAuthorization(requestedFnc, this.permissions);
    }
    /**
     * Verify if caller is authorized to submit request for given operation
     * Groups of functions can be customised sa that each host has only the privileges he really needs:
     * 1. : create a new constant for your group of functions, eg. ACL_QUORUM_MANAGEMENT (see examples)
     * 2. : list all the functions that your new set will contain; each function as one case. at the end of the set throw an exception
     * 3. : perform logical and on host's permissions and your new set constant -> != 0
     *
     * @param requestedFnc function to be checked
     */
    public void VerifyCallerAuthorization(short requestedFnc, short permissions) throws MPCException{

        // comparing requested function against ACL
        if (permissions == ACL_FULL_PRIVILEGES) {
            return;
        }

        switch (requestedFnc) {
            case mpc.StateModel.FNC_INS_PERSONALIZE_SET_USER_AUTH_PUBKEY:
                if (permissions == ACL_FULL_PRIVILEGES) return; // only hosts with full privileges can set acl
                throw new HostNotAllowedException(); // if reached, host is not allowed to perform this operation

                // Quorum management functions - ACL_QUORUM_MANAGEMENT
            case mpc.StateModel.FNC_QuorumContext_SetupNew:
            case mpc.StateModel.FNC_QuorumContext_Reset:
            case mpc.StateModel.FNC_QuorumContext_GetState:
            case mpc.StateModel.FNC_QuorumContext_GenerateRandomData:
                if ((permissions & ACL_QUORUM_MANAGEMENT) != 0) return;
                throw new HostNotAllowedException(); // if reached, host is not allowed to perform this operation

                // Key generation functions - ACL_KEY_GENERATION
            case mpc.StateModel.FNC_QuorumContext_GetXi:
            case mpc.StateModel.FNC_QuorumContext_GetYi:
            case mpc.StateModel.FNC_QuorumContext_GetY:
            case mpc.StateModel.FNC_QuorumContext_RetrieveCommitment:
            case mpc.StateModel.FNC_QuorumContext_SetYs:
            case mpc.StateModel.FNC_QuorumContext_StoreCommitment:
            case mpc.StateModel.FNC_QuorumContext_GenerateExampleBackdooredKeyPair:
            case mpc.StateModel.FNC_QuorumContext_InitAndGenerateKeyPair:
                if ((permissions & ACL_KEY_GENERATION) != 0) return;
                throw new HostNotAllowedException(); // if reached, host is not allowed to perform this operation

                // Sing functions - ACL_SIGN
            case mpc.StateModel.FNC_QuorumContext_Sign_RetrieveRandomRi:
            case mpc.StateModel.FNC_QuorumContext_Sign:
            case mpc.StateModel.FNC_QuorumContext_Sign_GetCurrentCounter:
                if ((permissions & ACL_SIGN) != 0) return;
                throw new HostNotAllowedException(); // if reached, host is not allowed to perform this operation

                // Decrypt functions - ACL_DECRYPT
            case mpc.StateModel.FNC_QuorumContext_DecryptShare:
                if ((permissions & ACL_DECRYPT) != 0) return;
                throw new HostNotAllowedException(); // if reached, host is not allowed to perform this operation

                // Encrypt functions ACL_ENCRYPT
            case mpc.StateModel.FNC_QuorumContext_Encrypt:
                if ((permissions & ACL_ENCRYPT) != 0) return;
                throw new HostNotAllowedException(); // if reached, host is not allowed to perform this operation

                // function groups that overlay
            case StateModel.FNC_QuorumContext_Invalidate:
                if ((permissions & (ACL_QUORUM_MANAGEMENT | ACL_KEY_GENERATION)) != 0) return;
                throw new HostNotAllowedException(); // if reached, host is not allowed to perform this operation

            default:
                throw new HostNotAllowedException(); // if reached, host is not allowed to perform this operation
        }
    }
}
