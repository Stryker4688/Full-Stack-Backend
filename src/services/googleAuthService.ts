// backend/src/services/googleAuthService.ts
import { logger } from '../config/logger';

export class GoogleAuthService {

    static initialize() {
        console.log('✅ Google Auth Service Initialized (TokenInfo API)');
        logger.info('Google Auth Service Initialized');
    }

    // 🆕 متد جدید برای تبدیل authorization code به idToken
    static async getTokenFromCode(code: string): Promise<string> {
        try {
            console.log('🔄 Exchanging authorization code for tokens...');

            const response = await fetch('https://oauth2.googleapis.com/token', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    code: code,
                    client_id: process.env.GOOGLE_CLIENT_ID!,
                    client_secret: process.env.GOOGLE_CLIENT_SECRET!,
                    redirect_uri: 'http://localhost:3000',
                    grant_type: 'authorization_code'
                })
            });

            console.log('🔍 Token exchange response status:', response.status);

            if (!response.ok) {
                const errorText = await response.text();
                console.error('❌ Token exchange failed:', errorText);
                throw new Error(`Token exchange failed: ${response.status} - ${errorText}`);
            }

            const tokens = await response.json();
            console.log('✅ Successfully exchanged code for tokens');

            if (!tokens.id_token) {
                throw new Error('No ID token received from Google');
            }

            return tokens.id_token;

        } catch (error: any) {
            console.error('❌ Failed to exchange authorization code:');
            console.error('🔍 Error details:', error.message);
            throw new Error(`Failed to exchange authorization code: ${error.message}`);
        }
    }

    // متد موجود برای verify token
    static async verifyToken(idToken: string) {
        try {
            console.log('🔧 Verifying token via Google TokenInfo API...');

            const response = await fetch(
                `https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(idToken)}`
            );

            console.log('🔍 Google API response status:', response.status);

            if (!response.ok) {
                const errorText = await response.text();
                console.error('❌ Google API error:', errorText);
                throw new Error(`Google API error: ${response.status} - ${errorText}`);
            }

            const payload = await response.json();
            console.log('✅ Token verified successfully');
            console.log('👤 User email:', payload.email);
            console.log('🎯 Audience:', payload.aud);

            // بررسی audience
            if (payload.aud !== process.env.GOOGLE_CLIENT_ID) {
                console.error('❌ Audience mismatch:', {
                    expected: process.env.GOOGLE_CLIENT_ID,
                    actual: payload.aud
                });
                throw new Error('Invalid token audience');
            }

            return {
                googleId: payload.sub,
                email: payload.email,
                name: payload.name,
                picture: payload.picture,
                emailVerified: payload.email_verified === 'true'
            };

        } catch (error: any) {
            console.error('❌ Google token verification failed:');
            console.error('🔍 Error details:', error.message);
            throw new Error('Invalid Google token: ' + error.message);
        }
    }
}