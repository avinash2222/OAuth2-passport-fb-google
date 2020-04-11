require('dotenv').config();
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcryptjs');
const JWT = require('jsonwebtoken');
var passportLocalMongoose = require('passport-local-mongoose');

var address = new Schema({
    secondary_phone_number : {
        type : Number,
        trim: true
    },
    state : {
        type : String
    },
    city : {
        type : String
    },
    pincode : {
        type : Number,
        trim: true
    },
    locality : {
        type : String
    },
    landmark : {
        type : String
    },
    full_address : {
        type : String
    }
});


var newSchema = new Schema({
    phone_number : {
        type : Number,
        // required:"enter phone no",
        trim : true,
        // unique : true
    },
    // username automatically added by passport-local-mongoose plugin
    // username : {
    //     type : String,
    //     trim : true
    // },
    firstname : {
        type : String,
        // required : "enter first name",
        trim: true
    },
    facebookId : String,
    lastname : {
        type : String,
        // required : "enter last name",
        trim: true   
    }, 
    email : {
        type : String,
        trim: true
    },
    organisation : {
        type : String
    },
    sub_organisation : {
        type : String
    },
    notes : {
        type : String,
        trim : true
    },
    active : {
        type : Boolean,
    },
    address : address,
    birthday : [Date],
    gender : {
        type : String,
        enum : ['male', 'female']
    },
    // password automatically added by passport-local-mongoose plugin
    // password : {
    //     type : String,
    //     trim : true,
    //     required : "enter password"
    // },
    image : { 
        type : String
    },
    role: {
        type: String,
        enum : ['user', 'operator', 'admin'],
        default: 'user',
        required: 'Specify user type',
    },
  },{
  timestamps : true
  },{
    versionKey: false
});

newSchema.statics.hashPwd = function (req, res, next) {
    const saltRounds = 10;
    bcrypt.hash(req.body.password, saltRounds)
    .then(function(hash) {
        req.body.password = hash;
        next();
    }).catch(err => {
        res.status(500).send({
            message: `Error:${err.message}`
            });
        });
};

newSchema.statics.signToken = newUser => {
    return JWT.sign({
        role : newUser.role,
        // mobile : newUser.phoneNumber,
        userid : newUser.userid,
        iss : 'omniwyse',
        sub : newUser.id,
        iat : new Date().getTime(),
        exp : new Date().setDate(new Date().getDate()+1)
    },process.env.JWT_SECRET);
};


newSchema.plugin(passportLocalMongoose);

module.exports = mongoose.model("User",newSchema);