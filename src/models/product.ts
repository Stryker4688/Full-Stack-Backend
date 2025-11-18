// backend/src/models/product.ts - FIXED
import mongoose from 'mongoose';

export interface IProduct extends mongoose.Document {
    _id: mongoose.Types.ObjectId;
    name: string;
    description: string;
    price: number;
    originalPrice?: number;
    category: 'coffee_beans' | 'brewing_equipment' | 'accessories' | 'gift_sets';
    roastLevel: 'light' | 'medium' | 'dark' | 'espresso';
    flavorProfile: string[];
    origin?: string;
    weight: number;
    inStock: boolean;
    stockQuantity: number;
    isFeatured: boolean;
    isActive: boolean;
    images: string[];
    createdBy: mongoose.Types.ObjectId;
    createdAt: Date;
    updatedAt: Date;
    searchKeywords: string[];
}

const productSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true,
        maxlength: 100
    },
    description: {
        type: String,
        required: true,
        maxlength: 1000
    },
    price: {
        type: Number,
        required: true,
        min: 0
    },
    originalPrice: {
        type: Number,
        min: 0
    },
    category: {
        type: String,
        enum: ['coffee_beans', 'brewing_equipment', 'accessories', 'gift_sets'],
        required: true
    },
    roastLevel: {
        type: String,
        enum: ['light', 'medium', 'dark', 'espresso'],
        required: true
    },
    flavorProfile: [{
        type: String,
        trim: true
    }],
    origin: {
        type: String,
        trim: true
    },
    weight: {
        type: Number,
        required: true,
        min: 0
    },
    inStock: {
        type: Boolean,
        default: true
    },
    stockQuantity: {
        type: Number,
        required: true,
        min: 0,
        default: 0
    },
    isFeatured: {
        type: Boolean,
        default: false
    },
    isActive: {
        type: Boolean,
        default: true
    },
    images: [{
        type: String
    }],
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    searchKeywords: [{
        type: String,
        trim: true,
        lowercase: true
    }]
}, {
    timestamps: true
});

// Define ALL indexes
productSchema.index({
    name: 'text',
    description: 'text',
    origin: 'text',
    flavorProfile: 'text',
    searchKeywords: 'text'
});

productSchema.index({ category: 1, isActive: 1 });
productSchema.index({ isFeatured: 1, isActive: 1 });
productSchema.index({ roastLevel: 1 });
productSchema.index({ price: 1 });
productSchema.index({ createdAt: -1 });
productSchema.index({ 'searchKeywords': 1 });
productSchema.index({ inStock: 1 });
productSchema.index({ createdBy: 1 });

// Virtual for discount percentage
productSchema.virtual('discountPercentage').get(function () {
    if (this.originalPrice && this.originalPrice > this.price) {
        return Math.round(((this.originalPrice - this.price) / this.originalPrice) * 100);
    }
    return 0;
});

// Middleware for auto-generating search keywords
productSchema.pre('save', function (next) {
    this.inStock = this.stockQuantity > 0;

    // Generate search keywords
    const keywords = new Set<string>();

    this.name.toLowerCase().split(' ').forEach(word => {
        if (word.length > 2) keywords.add(word);
    });

    this.description.toLowerCase().split(' ').forEach(word => {
        if (word.length > 3) keywords.add(word);
    });

    this.flavorProfile.forEach(flavor => {
        flavor.toLowerCase().split(' ').forEach(word => {
            if (word.length > 2) keywords.add(word);
        });
    });

    if (this.origin) {
        this.origin.toLowerCase().split(' ').forEach(word => {
            if (word.length > 2) keywords.add(word);
        });
    }

    keywords.add(this.category);
    keywords.add(this.roastLevel);

    this.searchKeywords = Array.from(keywords);
    next();
});

productSchema.set('toJSON', {
    virtuals: true,
    transform: function (doc, ret) {
        const { __v, ...rest } = ret;
        return rest;
    }
});

export default mongoose.model<IProduct>('Product', productSchema);