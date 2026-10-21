package com.auth.reglog.service;

import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

/**
 * Email service backed by Spring Mail / Jakarta Mail.
 * Configure SMTP credentials via environment variables.
 *
 * In automated tests, this bean is replaced by a mock.
 * Real email delivery requires valid SMTP configuration in the environment.
 */
@Service
public class EmailService {

    private static final Logger log = LoggerFactory.getLogger(EmailService.class);

    private final JavaMailSender mailSender;

    @Value("${app.mail.from}")
    private String fromAddress;

    public EmailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    /**
     * Send the OTP to the user's registered email address.
     *
     * @param toEmail        recipient email
     * @param recipientName  recipient's full name (for personalization)
     * @param otp            the raw 6-digit OTP (not logged in production)
     * @param expiryMinutes  OTP validity in minutes
     */
    public void sendOtpEmail(String toEmail, String recipientName, String otp, int expiryMinutes) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromAddress);
            helper.setTo(toEmail);
            helper.setSubject("Your Password Recovery OTP");
            helper.setText(buildOtpEmailBody(recipientName, otp, expiryMinutes), true);

            mailSender.send(message);
        } catch (Exception e) {
            // Re-throw so AuthService can handle the failure safely
            throw new RuntimeException("Failed to send OTP email: " + e.getMessage(), e);
        }
    }

    private String buildOtpEmailBody(String name, String otp, int expiryMinutes) {
        return """
            <html>
            <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <h2>Password Recovery OTP</h2>
              <p>Hello %s,</p>
              <p>You requested a password reset for your account.</p>
              <p>Your one-time password (OTP) is:</p>
              <div style="background: #f4f4f4; padding: 20px; text-align: center; font-size: 32px;
                          font-weight: bold; letter-spacing: 8px; border-radius: 8px; margin: 20px 0;">
                %s
              </div>
              <p><strong>This OTP is valid for %d minutes.</strong></p>
              <p>If you did not request this, please ignore this email. Do not share this OTP with anyone.</p>
              <hr/>
              <p style="color: #888; font-size: 12px;">This is an automated email. Please do not reply.</p>
            </body>
            </html>
            """.formatted(name, otp, expiryMinutes);
    }
}
