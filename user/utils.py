# utils.py
from datetime import timedelta

import pyotp
from django.utils import timezone

def send_otp(request, *, user, interval_seconds: int = 60, ttl_minutes: int = 5):
    """
    Generates a per-session OTP secret and stores an expiry as ISO8601 string.
    Sends the current OTP code via your preferred channel (email/SMS).

    Session keys used:
      - 'otp_secret_key' (str)
      - 'otp_valid_date' (ISO8601 string, timezone-aware)
      - 'pre_2fa_user_id' (int)    # set in the view too, but harmless to ensure here
      - 'pre_2fa_username' (str)
    """
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret, interval=interval_seconds)
    code = totp.now()  # If you need to include the code in an email/SMS

    expires_at = timezone.now() + timedelta(minutes=ttl_minutes)

    # Store in session; ISO string plays nicely with JSON serializer
    request.session['otp_secret_key'] = secret
    request.session['otp_valid_date'] = expires_at.isoformat()

    # Ensure identity present (view already sets these, but keep them in sync)
    if 'pre_2fa_user_id' not in request.session:
        request.session['pre_2fa_user_id'] = user.pk
    if 'pre_2fa_username' not in request.session:
        request.session['pre_2fa_username'] = getattr(user, 'username', None)

    print(code)
