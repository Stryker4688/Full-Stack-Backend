// backend/src/models/Testimonials.ts
import mongoose from 'mongoose';

export interface ITestimonial extends mongoose.Document {
    _id: mongoose.Types.ObjectId;
    name: string;
    email: string;
    message: string;
    rating: number;
    isApproved: boolean;
    isActive: boolean;
    createdAt: Date;
    updatedAt: Date;
}

const testimonialSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true,
        maxlength: 50
    },
    email: {
        type: String,
        required: true,
        trim: true,
        lowercase: true
    },
    message: {
        type: String,
        required: true,
        trim: true,
        maxlength: 500
    },
    rating: {
        type: Number,
        required: true,
        min: 1,
        max: 5,
        default: 5
    },
    isApproved: {
        type: Boolean,
        default: false
    },
    isActive: {
        type: Boolean,
        default: true
    }
}, {
    timestamps: true
});

// Define indexes
testimonialSchema.index({ isApproved: 1, isActive: 1 });
testimonialSchema.index({ rating: -1 });
testimonialSchema.index({ createdAt: -1 });
testimonialSchema.index({ email: 1 }); // Added for better querying

testimonialSchema.set('toJSON', {
    transform: function (doc, ret) {
        const { __v, ...rest } = ret;
        return rest;
    }
});

export default mongoose.model<ITestimonial>('Testimonial', testimonialSchema);