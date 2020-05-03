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

class DuplicateHostIdException extends MPCException {
    public DuplicateHostIdException() {
        super();
    }
}

class HostNotAllowedException extends MPCException {
    public HostNotAllowedException() {
        super();
    }
}

class InvalidPacketSignatureException extends MPCException {
    public InvalidPacketSignatureException() {
        super();
    }
}

