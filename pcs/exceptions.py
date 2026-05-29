from __future__ import annotations
from enum import IntEnum


class ErrorCode(IntEnum):
    ERR_FORMAT          = 0x01
    ERR_AUTH            = 0x02
    ERR_HMAC            = 0x03
    ERR_TIMEOUT         = 0x04
    ERR_PAYLOAD_TOO_BIG = 0x05
    ERR_RATE_LIMIT      = 0x06
    ERR_UNKNOWN_TYPE    = 0x07


CRITICAL_ERRORS = frozenset({
    ErrorCode.ERR_FORMAT,
    ErrorCode.ERR_AUTH,
    ErrorCode.ERR_HMAC,
    ErrorCode.ERR_TIMEOUT,
})


class PCSError(Exception):
    pass


class PCSFrameError(PCSError):
    def __init__(self, error_code: ErrorCode, message: str = "") -> None:
        self.error_code = error_code
        self.is_critical = error_code in CRITICAL_ERRORS
        super().__init__(f"[{error_code.name}] {message}")


class PCSHMACError(PCSFrameError):
    def __init__(self) -> None:
        super().__init__(ErrorCode.ERR_HMAC, "HMAC verification failed")


class PCSAuthError(PCSFrameError):
    def __init__(self, message: str = "Authentication failed") -> None:
        super().__init__(ErrorCode.ERR_AUTH, message)


class PCSPayloadTooLargeError(PCSFrameError):
    def __init__(self, size: int = 0) -> None:
        msg = f"Payload size {size} exceeds MAX_PAYLOAD_SIZE" if size else "Payload too large"
        super().__init__(ErrorCode.ERR_PAYLOAD_TOO_BIG, msg)


class PCSUnknownTypeError(PCSFrameError):
    def __init__(self, type_byte: int) -> None:
        super().__init__(ErrorCode.ERR_UNKNOWN_TYPE, f"Unknown message type: 0x{type_byte:02X}")


class PCSRateLimitError(PCSFrameError):
    def __init__(self) -> None:
        super().__init__(ErrorCode.ERR_RATE_LIMIT, "Rate limit exceeded")


class PCSIncompleteFrameError(PCSError):
    pass


class PCSReplayAttackError(PCSError):
    pass
