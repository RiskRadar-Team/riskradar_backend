import crypto from "crypto";

/**
 * Generate a cryptographically secure 6-digit OTP.
 */
export function generateOtp() {
  return crypto.randomInt(100000, 1000000).toString();
}

/**
 * Hash OTP before storing it in the database.
 *
 * We never store the actual OTP.
 */
export function hashOtp(otp) {
  return crypto.createHash("sha256").update(otp).digest("hex");
}

/**
 * Calculate OTP expiration time.
 *
 * Default: 10 minutes.
 */
export function getOtpExpiry() {
  const expiryMinutes = Number(
    process.env.PASSWORD_RESET_OTP_EXPIRES_MINUTES || 10,
  );

  return new Date(Date.now() + expiryMinutes * 60 * 1000);
}
