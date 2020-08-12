package mpctestclient;

/**
 * Exceptions used when a card returns an error code.
 *
 * @author Kristian Mika
 */
class MPCException extends Exception {
    public MPCException() {
    }

    public MPCException(String s) {
        super(s);
    }

    public MPCException(Throwable throwable) {
        super(throwable);
    }

}

/**
 * Exception used when a card returns the SW_DUPLICATE_HOST_ID error code.
 * This happens when a host with a duplicate ID wants to join the protocol.
 */
class DuplicateHostIdException extends MPCException {
    public DuplicateHostIdException() {
        super();
    }
}

/**
 * Used when a card returns SW_INVALID_HOST_ID error code.
 * This happens when the card can't identify a host. The host might have skipped the SetAuthPubkey phase.
 */
class InvalidHostIdException extends MPCException {
    public InvalidHostIdException() {
        super();
    }
}

/**
 * Used when a card returns the SW_HOSTNOTALLOWED error code.
 * This happens when a host requests an operation he is not permitted to request.
 */
class HostNotAllowedException extends MPCException {
    public HostNotAllowedException() {
        super();
    }
}

/**
 * Used when the APDU signature sent by a card is not correct.
 */
class InvalidCardSignatureException extends MPCException {
    public InvalidCardSignatureException() {
        super();
    }
}

/**
 * Used when a card returns the SW_INVALID_PACKET_SIGNATURE error code.
 * This means that the APDU signature sent by a host is not correct.
 */
class InvalidHostSignatureException extends MPCException {
    public InvalidHostSignatureException() {
        super();
    }
}

/**
 * Used when a card returns the SW_FUNCTINNOTALLOWED error code.
 * This means that the quorum is in a state that doesn't allow to perform the requested query.
 */
class FunctionNotAllowedException extends MPCException {
    public FunctionNotAllowedException() {
        super();
    }

    public FunctionNotAllowedException(String s) {
        super(s);
    }
}

/**
 * Used when a card returns the SW_INCORRECTSTATETRANSITION error code.
 * This may happen when a host submits queries in a wrong order, e.g. request to sing data without previous keyGeneration.
 */
class TransitionNotAllowedException extends MPCException {
    public TransitionNotAllowedException() {
        super();
    }
}

/**
 * Used when a card returns the SW_APPLET_LOCKED error code.
 */
class AppletLockedException extends MPCException {
    public AppletLockedException() {
        super();
    }
}

