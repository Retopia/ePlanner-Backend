// emailService.js
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config();

class EmailService {
    constructor() {
        // Create reusable transporter
        // Using Gmail as an example - you can switch to other SMTP services
        this.transporter = nodemailer.createTransport({
            service: 'gmail',  // Built in support for Gmail
            auth: {
                user: process.env.EMAIL_USER,       // Your Gmail address
                pass: process.env.EMAIL_APP_PASSWORD // Gmail App Password
            }
        });
    }

    // Method to send password reset email
    async sendPasswordResetEmail(to, resetToken) {
        const resetLink = `${process.env.FRONTEND_ADDRESS}/reset-password/${resetToken}`;
        
        const mailOptions = {
            from: {
                name: 'E-Planner',
                address: process.env.EMAIL_USER
            },
            to,
            subject: 'Reset Your Password',
            text: `Please use the following link to reset your password: ${resetLink}`,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #333;">Password Reset Request</h2>
                    <p>You have requested to reset your password. Please click the link below to proceed:</p>
                    <a href="${resetLink}" 
                       style="display: inline-block; 
                              padding: 10px 20px; 
                              background-color: #4CAF50; 
                              color: white; 
                              text-decoration: none; 
                              border-radius: 5px; 
                              margin: 20px 0;">
                        Reset Password
                    </a>
                    <p>If you didn't request this, please ignore this email or contact support if you have concerns.</p>
                    <p>This link will expire in 1 hour.</p>
                    <hr style="border: 1px solid #eee; margin: 20px 0;">
                    <p style="color: #666; font-size: 12px;">This is an automated email, please do not reply.</p>
                </div>
            `
        };

        try {
            const info = await this.transporter.sendMail(mailOptions);
            console.log('Password reset email sent:', info.messageId);
            return true;
        } catch (error) {
            console.error('Error sending password reset email:', error);
            throw error;
        }
    }

    // Method to verify email configuration
    async verifyConnection() {
        try {
            await this.transporter.verify();
            console.log('Email service is ready');
            return true;
        } catch (error) {
            console.error('Email service verification failed:', error);
            throw error;
        }
    }
}

// Create and export a singleton instance
const emailService = new EmailService();
export default emailService;