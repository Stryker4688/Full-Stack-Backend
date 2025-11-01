// backend/src/services/emailService.ts
import nodemailer from 'nodemailer';
import { logger } from '../config/logger';

export class EmailService {
    private static transporter: nodemailer.Transporter;

    static initialize() {
        if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
            console.error('❌ SMTP configuration is missing');
            logger.error('SMTP configuration is missing');
            return;
        }

        this.transporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST || 'smtp.gmail.com',
            port: parseInt(process.env.SMTP_PORT || '587'),
            secure: false,
            auth: {
                user: process.env.SMTP_USER,
                pass: process.env.SMTP_PASS
            },
            tls: {
                rejectUnauthorized: false
            }
        });

        console.log('✅ Gmail SMTP Service Initialized');
        logger.info('Gmail SMTP Service Initialized');
    }

    static async testSMTPConnection(): Promise<boolean> {
        try {
            if (!this.transporter) {
                console.error('❌ SMTP transporter not initialized');
                return false;
            }

            await this.transporter.verify();
            console.log('✅ Gmail SMTP Connection Successful');
            logger.info('Gmail SMTP Connection Successful');
            return true;
        } catch (error: any) {
            console.error('❌ Gmail SMTP Connection Failed:', error.message);
            logger.error('Gmail SMTP Connection Failed', { error: error.message });
            return false;
        }
    }

    static async sendVerificationCode(email: string, code: string, name: string): Promise<boolean> {
        try {
            const mailOptions = {
                from: `"Brew Haven" <${process.env.SMTP_FROM_EMAIL}>`,
                to: email,
                subject: 'Your 6-Digit Verification Code - Brew Haven',
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <div style="background: linear-gradient(135deg, #d97706, #b45309); padding: 30px; text-align: center; color: white;">
                            <h1 style="margin: 0; font-size: 28px;">☕ Brew Haven</h1>
                            <p style="margin: 10px 0 0 0; opacity: 0.9;">Email Verification Code</p>
                        </div>
                        
                        <div style="padding: 30px; background: #f8fafc;">
                            <h2 style="color: #1f2937; margin-bottom: 20px;">Hello ${name},</h2>
                            
                            <p style="color: #4b5563; line-height: 1.6; margin-bottom: 25px;">
                                Thank you for registering with Brew Haven! Use the 6-digit verification code below to complete your registration:
                            </p>
                            
                            <div style="text-align: center; margin: 30px 0;">
                                <div style="background: linear-gradient(135deg, #d97706, #b45309); color: white; padding: 25px; border-radius: 12px; 
                                          font-size: 36px; font-weight: bold; letter-spacing: 10px; display: inline-block;
                                          font-family: 'Courier New', monospace; min-width: 250px; text-align: center;">
                                    ${code}
                                </div>
                            </div>
                            
                            <div style="background: #fef3c7; border: 1px solid #f59e0b; padding: 15px; border-radius: 8px; margin: 20px 0;">
                                <p style="color: #92400e; margin: 0; text-align: center; font-size: 14px; font-weight: bold;">
                                    ⏰ This code will expire in 10 minutes
                                </p>
                            </div>
                            
                            <p style="color: #6b7280; font-size: 14px; text-align: center;">
                                Enter this 6-digit code on the verification page to activate your account.<br>
                                If you didn't request this code, please ignore this email.
                            </p>
                        </div>
                        
                        <div style="background: #1f2937; padding: 20px; text-align: center; color: #9ca3af;">
                            <p style="margin: 0; font-size: 12px;">
                                &copy; 2024 Brew Haven. All rights reserved.<br>
                                123 Coffee Street, Brew City
                            </p>
                        </div>
                    </div>
                `
            };

            const info = await this.transporter.sendMail(mailOptions);

            console.log('✅ Verification code email sent:', {
                to: email,
                code: code,
                messageId: info.messageId
            });

            logger.info('Verification code email sent successfully', {
                email,
                code,
                messageId: info.messageId
            });
            return true;
        } catch (error: any) {
            console.error('❌ Failed to send verification code email:', error.message);
            logger.error('Failed to send verification code email', {
                email,
                error: error.message
            });
            return false;
        }
    }

    static async sendWelcomeEmail(email: string, name: string): Promise<boolean> {
        try {
            const mailOptions = {
                from: `"Brew Haven" <${process.env.SMTP_FROM_EMAIL}>`,
                to: email,
                subject: 'Welcome to Brew Haven! 🎉',
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <div style="background: linear-gradient(135deg, #d97706, #b45309); padding: 30px; text-align: center; color: white;">
                            <h1 style="margin: 0; font-size: 28px;">☕ Welcome to Brew Haven!</h1>
                        </div>
                        
                        <div style="padding: 30px; background: #f8fafc;">
                            <h2 style="color: #1f2937; margin-bottom: 20px;">Hello ${name},</h2>
                            
                            <p style="color: #4b5563; line-height: 1.6; margin-bottom: 20px;">
                                Your email has been successfully verified! Welcome to our community of coffee enthusiasts.
                            </p>
                            
                            <p style="color: #4b5563; line-height: 1.6; margin-bottom: 25px;">
                                Now you can:
                            </p>
                            
                            <ul style="color: #4b5563; line-height: 1.6; margin-bottom: 25px;">
                                <li>🎯 Explore our premium coffee beans collection</li>
                                <li>⭐ Get personalized coffee recommendations</li>
                                <li>💰 Access exclusive member discounts</li>
                                <li>📦 Track your orders and brewing history</li>
                            </ul>
                            
                            <div style="text-align: center; margin: 30px 0;">
                                <a href="${process.env.FRONTEND_URL}" 
                                   style="background: #d97706; color: white; padding: 12px 30px; 
                                          text-decoration: none; border-radius: 8px; font-weight: bold;
                                          display: inline-block; font-size: 16px;">
                                    Start Exploring
                                </a>
                            </div>
                        </div>
                        
                        <div style="background: #1f2937; padding: 20px; text-align: center; color: #9ca3af;">
                            <p style="margin: 0; font-size: 12px;">
                                &copy; 2024 Brew Haven. All rights reserved.
                            </p>
                        </div>
                    </div>
                `
            };

            const info = await this.transporter.sendMail(mailOptions);
            logger.info('Welcome email sent successfully', {
                email,
                messageId: info.messageId
            });
            return true;
        } catch (error: any) {
            console.error('❌ Failed to send welcome email:', error.message);
            logger.error('Failed to send welcome email', {
                email,
                error: error.message
            });
            return false;
        }
    }
}