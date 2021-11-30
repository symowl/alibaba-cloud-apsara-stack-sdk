# coding=utf-8
import hmac
from aliyunsdkcore.compat import ensure_string
from aliyunsdkcore.compat import ensure_bytes
from aliyunsdkcore.compat import b64_encode_bytes
from aliyunsdkcore.acs_exception.exceptions import ClientException

def get_sign_string(source, secret):
    source = ensure_bytes(source)
    secret = ensure_bytes(secret)
    signature=""
    try:
        import smalgo
        signature = smalgo.sm3Hmac(secret,source)
        signature = ensure_string(b64_encode_bytes(signature).strip())
    except ImportError:
        raise ClientException(
                "SDK.PackageInvalid",
                "smalgo not found")
    return signature


def get_signer_name():
    return "HMAC-SM3"


def get_signer_version():
    return "1.0"


def get_signer_type():
    return ""