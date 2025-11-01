// backend/src/models/users.ts - FIXED
import mongoose from 'mongoose';

export interface IUser extends mongoose.Document {
    _id: mongoose.Types.ObjectId;
    name: string;
    email: string;
    password: string;
    role: 'user' | 'admin' | 'super_admin';
    isActive: boolean;
    lastLogin?: Date;
    createdAt: Date;
    updatedAt: Date;
    googleId?: string;
    authProvider: 'local' | 'google';
    emailVerified: boolean;
    emailVerificationCode?: string;
    emailVerificationCodeExpires?: Date;
    emailVerificationSentAt?: Date;
    username?: string;
}

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true, // This creates an index automatically
        lowercase: true
        // ❌ REMOVED: index: true (duplicate)
    },
    username: {
        type: String,
        sparse: true,
        trim: true
    },
    password: {
        type: String,
        required: function (this: any) {
            return this.authProvider === 'local';
        },
        minlength: 6
    },
    role: {
        type: String,
        enum: ['user', 'admin', 'super_admin'],
        default: 'user'
        // ❌ REMOVED: index: true (define in schema.index below)
    },
    isActive: {
        type: Boolean,
        default: true
        // ❌ REMOVED: index: true (define in schema.index below)
    },
    lastLogin: {
        type: Date,
        default: Date.now
    },
    googleId: {
        type: String,
        sparse: true,
        unique: true // This creates an index automatically
    },
    authProvider: {
        type: String,
        enum: ['local', 'google'],
        default: 'local'
    },
    emailVerified: {
        type: Boolean,
        default: false
    },
    emailVerificationCode: {
        type: String,
        sparse: true
    },
    emailVerificationCodeExpires: {
        type: Date
    },
    emailVerificationSentAt: {
        type: Date
    }
}, {
    timestamps: true
});

// ✅ Define indexes ONLY here (not in field definitions)
userSchema.index({ role: 1 });
userSchema.index({ isActive: 1 });
userSchema.index({ createdAt: -1 });
userSchema.index({ authProvider: 1 }); // Added for better querying
userSchema.index({ emailVerified: 1 }); // Added for better querying

// Remove duplicate index definitions - keep only one method
userSchema.set('toJSON', {
    virtuals: true,
    transform: function (doc, ret) {
        const retObj = ret as any;
        delete retObj.password;
        delete retObj.emailVerificationCode;
        delete retObj.emailVerificationCodeExpires;
        return retObj;
    }
});

export default mongoose.model<IUser>('User', userSchema);