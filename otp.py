import hmac
import base64
import struct
import hashlib
import time   

def hotp(secret_b32: str, counter: int, digits: int = 6) -> str:
    """
    Sinh mã HOTP (HMAC-based One-Time Password).
    
    secret_b32 : str   - secret key ở dạng Base32 (chuỗi)
    counter    : int   - bộ đếm
    digits     : int   - số chữ số OTP mong muốn (mặc định 6)
    
    Trả về: mã OTP dạng chuỗi, zero-padding nếu thiếu chữ số.
    """
    # Giải mã Base32 → bytes
    key = base64.b32decode(secret_b32, True)
    # Pack counter thành 8 byte big-endian
    msg = struct.pack(">Q", counter)
    # Tính HMAC-SHA1
    hmac_digest = hmac.new(key, msg, hashlib.sha1).digest()
    # Dynamic truncation: lấy offset 4 bit thấp của byte cuối
    offset = hmac_digest[-1] & 0x0F
    # Lấy 4 byte bắt đầu từ offset đó
    four_bytes = hmac_digest[offset:offset + 4]
    # Chuyển thành số nguyên 31 bit (bỏ bit dấu)
    code_int = struct.unpack(">I", four_bytes)[0] & 0x7FFFFFFF
    # Lấy modulo để có số chữ số mong muốn
    otp_int = code_int % (10 ** digits)
    # Trả về dạng chuỗi zero-padding
    return str(otp_int).zfill(digits)

def totp(secret_b32: str, step: int = 30, digits: int = 6) -> str:
    """
    Sinh mã TOTP (Time-based One-Time Password).
    
    secret_b32 : str - secret key dạng Base32
    step       : int - độ dài mỗi bước thời gian (mặc định 30 giây)
    digits     : int - số chữ số OTP
    
    Trả về: mã OTP dạng chuỗi
    """
    # Đếm số bước thời gian từ Epoch
    counter = int(time.time() // step)
    return hotp(secret_b32, counter, digits)

def time_remaining(step: int = 30) -> int:
    """
    Trả về số giây còn lại trước khi mã TOTP hiện tại thay đổi.
    
    step : int - độ dài mỗi bước thời gian (mặc định 30 giây)
    """
    return step - int(time.time()) % step

# Ví dụ secret base32 
secret = "JBSWY3DPEHPK3PXP"  # tương đương 'Hello!\xDE\xAD\xBE\xEF'

print("Mã TOTP hiện tại:", totp(secret))
print("Còn lại:", time_remaining(), "giây trước khi đổi mã")
# test trên google colab