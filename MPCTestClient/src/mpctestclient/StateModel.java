package mpctestclient;


/**
 * Class that represents a state model.
 * Controls if a requested function is allowed in a current state.
 */
public class StateModel {


    // Protocol state constants
    public static final short STATE_UNINITIALIZED = (short) -1;
    public static final short STATE_QUORUM_CLEARED = (short) 0;
    public static final short STATE_QUORUM_INITIALIZED = (short) 1;
    public static final short STATE_KEYGEN_PRIVATEGENERATED = (short) 3;
    public static final short STATE_KEYGEN_COMMITMENTSCOLLECTED = (short) 4;
    public static final short STATE_KEYGEN_SHARESCOLLECTED = (short) 5;
    public static final short STATE_KEYGEN_KEYPAIRGENERATED = (short) 6;
    public static final short STATE_USER_PUBKEYS_SET = (short) 7;
    public static final short FNC_QuorumContext_GetXi = (short) 0xf001;
    public static final short FNC_QuorumContext_GetYi = (short) 0xf002;
    public static final short FNC_QuorumContext_Invalidate = (short) 0xf003;
    public static final short FNC_QuorumContext_GetY = (short) 0xf004;
    public static final short FNC_QuorumContext_RetrieveCommitment = (short) 0xf005;
    public static final short FNC_QuorumContext_SetYs = (short) 0xf006;
    public static final short FNC_QuorumContext_StoreCommitment = (short) 0xf007;
    public static final short FNC_QuorumContext_GenerateExampleBackdooredKeyPair = (short) 0xf008;
    public static final short FNC_QuorumContext_InitAndGenerateKeyPair = (short) 0xf009;
    public static final short FNC_QuorumContext_GetState = (short) 0xf00a;
    public static final short FNC_QuorumContext_Reset = (short) 0xf00b;
    public static final short FNC_QuorumContext_SetupNew = (short) 0xf00c;
    public static final short FNC_QuorumContext_Encrypt = (short) 0xf010;
    public static final short FNC_QuorumContext_DecryptShare = (short) 0xf011;
    public static final short FNC_QuorumContext_Sign_RetrieveRandomRi = (short) 0xf012;
    public static final short FNC_QuorumContext_Sign = (short) 0xf013;
    public static final short FNC_QuorumContext_Sign_GetCurrentCounter = (short) 0xf014;
    public static final short FNC_QuorumContext_VerifyCallerAuthorization = (short) 0xf011;
    public static final short FNC_QuorumContext_GenerateRandomData = (short) 0xf012;
    public static final short FNC_QuorumContext_SetUserPubKey           = (short) 0xf017;
    public static final short FNC_INS_PERSONALIZE_SET_USER_AUTH_PUBKEY  = (short) 0xf018;

    private short STATE_KEYGEN = STATE_UNINITIALIZED;

    public void CheckAllowedFunction(short requestedFnc) throws MPCException {
        CheckAllowedFunction(requestedFnc, STATE_KEYGEN);
    }

    public short MakeStateTransition(short newState) throws MPCException {
        STATE_KEYGEN = MakeStateTransition(STATE_KEYGEN, newState);
        return STATE_KEYGEN;
    }

    public short GetState() {
        return STATE_KEYGEN;
    }

    private void CheckAllowedFunction(short requestedFnc, short currentState) throws MPCException {
        // Check for functions which can be called from any state
        switch (requestedFnc) {
            case FNC_QuorumContext_Reset:
                return;
            case FNC_QuorumContext_GetState:
                return;
            case FNC_QuorumContext_Invalidate:
                return;
        }

        // Check if function can be called from current state
        switch (currentState) {
            case STATE_QUORUM_CLEARED:
                if (requestedFnc == FNC_QuorumContext_SetupNew) return;
                throw new FunctionNotAllowedException();

            case STATE_QUORUM_INITIALIZED:
                if (requestedFnc == FNC_QuorumContext_SetUserPubKey) return;
                throw new FunctionNotAllowedException();

            case STATE_USER_PUBKEYS_SET:
                if (requestedFnc == FNC_QuorumContext_SetUserPubKey) return;
                if (requestedFnc == FNC_QuorumContext_InitAndGenerateKeyPair) return;
                throw new FunctionNotAllowedException();

            case STATE_KEYGEN_PRIVATEGENERATED:
                if (requestedFnc == FNC_QuorumContext_RetrieveCommitment) return;
                if (requestedFnc == FNC_QuorumContext_StoreCommitment) return;
                throw new FunctionNotAllowedException();

            case STATE_KEYGEN_COMMITMENTSCOLLECTED:
                if (requestedFnc == FNC_QuorumContext_SetYs) return;
                if (requestedFnc == FNC_QuorumContext_GetYi) return;
                throw new FunctionNotAllowedException();

            case STATE_KEYGEN_SHARESCOLLECTED:
                throw new FunctionNotAllowedException();

            case STATE_KEYGEN_KEYPAIRGENERATED:
                if (requestedFnc == FNC_QuorumContext_GetXi) return;
                if (requestedFnc == FNC_QuorumContext_GetY) return;
                if (requestedFnc == FNC_QuorumContext_Encrypt) return;
                if (requestedFnc == FNC_QuorumContext_DecryptShare) return;
                if (requestedFnc == FNC_QuorumContext_Sign_RetrieveRandomRi) return;
                if (requestedFnc == FNC_QuorumContext_Sign) return;
                if (requestedFnc == FNC_QuorumContext_Sign_GetCurrentCounter) return;

                throw new FunctionNotAllowedException(); // if reached, function is not allowed in the given state

            default:
                throw new FunctionNotAllowedException("Unknown state");
        }
    }

    private short MakeStateTransition(short currentState, short newState) throws MPCException {
        // Check for functions which can be reached from any state
        switch (newState) {
            case STATE_QUORUM_CLEARED:
                return newState;
        }

        // Check if transition from currentState -> newState is allowed
        switch (currentState) {
            case STATE_QUORUM_CLEARED:
                if (newState == STATE_QUORUM_INITIALIZED) return newState;
                throw new TransitionNotAllowedException();
            case STATE_QUORUM_INITIALIZED:
                if (newState == STATE_USER_PUBKEYS_SET) return newState;
                throw new TransitionNotAllowedException();
            case STATE_USER_PUBKEYS_SET:
                if (newState == STATE_KEYGEN_PRIVATEGENERATED) return newState;
                if (newState == STATE_USER_PUBKEYS_SET) return newState;
                throw new TransitionNotAllowedException();
            case STATE_KEYGEN_PRIVATEGENERATED:
                if (newState == STATE_KEYGEN_COMMITMENTSCOLLECTED) return newState;
                throw new TransitionNotAllowedException();
            case STATE_KEYGEN_COMMITMENTSCOLLECTED:
                if (newState == STATE_KEYGEN_SHARESCOLLECTED) return newState;
                throw new TransitionNotAllowedException();
            case STATE_KEYGEN_SHARESCOLLECTED:
                if (newState == STATE_KEYGEN_KEYPAIRGENERATED) return newState;
                throw new TransitionNotAllowedException();
            case STATE_KEYGEN_KEYPAIRGENERATED:
                throw new TransitionNotAllowedException();
            default:
                throw new TransitionNotAllowedException();
        }
    }

}
