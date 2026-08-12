import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
  service: "gmail",

  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

/**
 * Send password reset OTP email.
 */
export async function sendPasswordResetOtpEmail({ email, fullName, otp }) {
  const expiryMinutes = Number(
    process.env.PASSWORD_RESET_OTP_EXPIRES_MINUTES || 10,
  );

  await transporter.sendMail({
    from: `"RiskRadar" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: "RiskRadar Password Reset OTP",

    text: `
Hello ${fullName},

We received a request to reset your RiskRadar password.

Your password reset OTP is:

${otp}

This OTP will expire in ${expiryMinutes} minutes.

If you did not request a password reset, please ignore this email.

Do not share this OTP with anyone.

Regards,
RiskRadar Team
    `.trim(),

    html: `
      <div
        style="
          font-family: Arial, sans-serif;
          max-width: 600px;
          margin: 0 auto;
          padding: 20px;
          color: #333;
        "
      >

        <h2 style="margin-bottom: 10px;">
          RiskRadar Password Reset
        </h2>

        <p>
          Hello ${fullName},
        </p>

        <p>
          We received a request to reset your RiskRadar password.
        </p>

        <p>
          Your password reset OTP is:
        </p>

        <div
          style="
            font-size: 32px;
            font-weight: bold;
            letter-spacing: 8px;
            text-align: center;
            padding: 20px;
            margin: 20px 0;
            background-color: #f3f4f6;
            border-radius: 8px;
          "
        >
          ${otp}
        </div>

        <p>
          This OTP will expire in
          <strong>${expiryMinutes} minutes</strong>.
        </p>

        <p>
          If you did not request a password reset, you can safely
          ignore this email.
        </p>

        <p>
          <strong>Do not share this OTP with anyone.</strong>
        </p>

        <p style="margin-top: 30px;">
          Regards,<br>
          <strong>RiskRadar Team</strong>
        </p>

      </div>
    `,
  });
}
