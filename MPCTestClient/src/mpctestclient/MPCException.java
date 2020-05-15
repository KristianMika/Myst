package mpctestclient;

/**
 * Exceptions used when a card returns an error code.
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

