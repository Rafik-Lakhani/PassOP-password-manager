const mongoose = require('mongoose');

const otpShchema = mongoose.Schema({
    email:{
        type: String,
        required: true,
    },
    otp:{
        type: String,
    },
    createdDate: {
        type: Date,
        default: Date.now
    },
    expiryDate: {
        type: Date,
        default: Date.now() + 600000
    }
});

module.exports = mongoose.model('otp', otpShchema);