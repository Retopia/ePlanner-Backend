// Import Mongoose
import mongoose from 'mongoose';
const { Schema } = mongoose;

// User Schema
// Password not required since Google users won't have a password
const userSchema = new Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    passwordHash: { type: String },
    googleId: { type: String },
    events: [{ type: Schema.Types.ObjectId, ref: 'Event' }]
});

// Event Schema
const eventSchema = new Schema({
    creator: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    title: { type: String, required: true },
    description: { type: String },
    location: { type: String, required: true },
    time: { type: Date, required: true },
    visibility: { type: String, enum: ['public', 'private'], default: 'private', required: true },
    tags: [{ type: String }],
    invitedUsers: [{ type: Schema.Types.ObjectId, ref: 'User' }],
    embeddedFiles: [
        {
            url: { type: String, required: true },
            fileType: { type: String, required: true },
            description: { type: String }
        }
    ]
}, {
    timestamps: true,
});

const resetTokenSchema = new Schema({
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    token: { type: String, required: true },
}, {
    timestamps: true,
});

// Create Models
const User = mongoose.model('User', userSchema);
const Event = mongoose.model('Event', eventSchema);
const ResetToken = mongoose.model('ResetToken', resetTokenSchema);

// Export Models
export { User, Event, ResetToken };
