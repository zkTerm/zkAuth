import * as OTPAuth from 'otpauth';

const TOTP_ISSUER = 'zkTerm';
const TOTP_ALGORITHM = 'SHA1';
const TOTP_DIGITS = 6;
const TOTP_PERIOD = 30;
const TOTP_WINDOW = 1;

export function verifyTOTP(code: string, secret: string): boolean {
  try {
    const normalizedCode = code.replace(/\s/g, '');
    
    if (!/^\d{6}$/.test(normalizedCode)) {
      return false;
    }

    const totp = new OTPAuth.TOTP({
      issuer: TOTP_ISSUER,
      algorithm: TOTP_ALGORITHM,
      digits: TOTP_DIGITS,
      period: TOTP_PERIOD,
      secret: OTPAuth.Secret.fromBase32(secret),
    });

    const delta = totp.validate({
      token: normalizedCode,
      window: TOTP_WINDOW,
    });

    return delta !== null;
  } catch (error) {
    console.error('[zk2fa] TOTP verification error:', error);
    return false;
  }
}

export function generateTOTPSecret(): string {
  const secret = new OTPAuth.Secret({ size: 20 });
  return secret.base32;
}

export function generateTOTPUri(secret: string, email: string, issuer?: string): string {
  const totp = new OTPAuth.TOTP({
    issuer: issuer || TOTP_ISSUER,
    label: email,
    algorithm: TOTP_ALGORITHM,
    digits: TOTP_DIGITS,
    period: TOTP_PERIOD,
    secret: OTPAuth.Secret.fromBase32(secret),
  });

  return totp.toString();
}

export async function generateQRCode(secret: string, email: string): Promise<string> {
  const uri = generateTOTPUri(secret, email);
  
  const qrCodeUrl = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(uri)}`;
  
  try {
    const response = await fetch(qrCodeUrl);
    if (!response.ok) {
      throw new Error('Failed to generate QR code');
    }
    
    const blob = await response.blob();
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onloadend = () => resolve(reader.result as string);
      reader.onerror = reject;
      reader.readAsDataURL(blob);
    });
  } catch (error) {
    console.error('[zk2fa] QR code generation error:', error);
    throw error;
  }
}

export function generateCurrentCode(secret: string): string {
  try {
    const totp = new OTPAuth.TOTP({
      issuer: TOTP_ISSUER,
      algorithm: TOTP_ALGORITHM,
      digits: TOTP_DIGITS,
      period: TOTP_PERIOD,
      secret: OTPAuth.Secret.fromBase32(secret),
    });

    return totp.generate();
  } catch (error) {
    console.error('[zk2fa] Error generating TOTP code:', error);
    throw error;
  }
}

export function getTimeRemaining(): number {
  const now = Math.floor(Date.now() / 1000);
  return TOTP_PERIOD - (now % TOTP_PERIOD);
}

export function getTOTPConfig() {
  return {
    issuer: TOTP_ISSUER,
    algorithm: TOTP_ALGORITHM,
    digits: TOTP_DIGITS,
    period: TOTP_PERIOD,
    window: TOTP_WINDOW,
  };
}
