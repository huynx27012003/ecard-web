const mongoose = require('mongoose');

const businessCardSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  selectedCardType: { type: mongoose.Schema.Types.ObjectId, ref: 'CardType', required: true },
  selectedTemplate: { type: mongoose.Schema.Types.ObjectId, ref: 'Template', required: true },
  selectedSubscriptionPlan: { type: mongoose.Schema.Types.ObjectId, ref: 'SubscriptionPlan', required: true },
  // Additional customizable fields based on the selected template
  templateFields: [
    {
      fieldName: String,  // Field name from the selected template
      fieldValue: String, // User-entered value for the field
    },
  ],
  Image: String,
  bgImg: String,
  bgColor: String,
  // Analytics
  viewCount: { type: Number, default: 0 },
  lastViewedAt: { type: Date },
  // Social Media Links
  socialLinks: {
    facebook: String,
    linkedin: String,
    zalo: String,
    tiktok: String,
    instagram: String,
    youtube: String,
  },
}, { timestamps: true });

const BusinessCard = mongoose.model('BusinessCard', businessCardSchema);
module.exports = BusinessCard;
