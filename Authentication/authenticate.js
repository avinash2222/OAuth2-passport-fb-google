//passport authentication
var User = require('../models/user');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var JwtStrategy = require('passport-jwt').Strategy;
var ExtractJwt = require('passport-jwt').ExtractJwt;
var jwt = require('jsonwebtoken'); // used to create, sign, and verify tokens

var FacebookTokenStrategy = require('passport-facebook-token');

exports.getToken = function(user) {
  return jwt.sign(user, process.env.secretKey,
      {expiresIn: 3600});
};

var opts = {};
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = process.env.secretKey;

exports.jwtPassport = passport.use(new JwtStrategy(opts,
  (jwt_payload, done) => {
      console.log("JWT payload: ", jwt_payload);
      User.findOne({_id: jwt_payload._id}, (err, user) => {
          if (err) {
              return done(err, false);
          }
          else if (user) {
              return done(null, user);
          }
          else {
              return done(null, false);
          }
      });
  }));

exports.verifyUser = passport.authenticate('jwt', {session: false});


exports.facebookPassport = passport.use(new FacebookTokenStrategy({
    clientID: process.env.clientId,
    clientSecret: process.env.clientSecret,
    callbackURL: "https:facebook.com"
}, (accessToken, refreshToken, profile, done) => {
    User.findOne({facebookId: profile.id}, (err, user) => {
        if (err) {
            return done(err, false);
        }
        if (!err && user !== null) {
            return done(null, user);
        }
        else {
            user = new User({ username: profile.displayName });
            user.facebookId = profile.id;
            user.firstname = profile.name.givenName;
            user.lastname = profile.name.familyName;
            user.image= profile.photos[0].value;
            user.email = profile.emails[0].value;
            // user.gender = profile.gender;
            
            user.save((err, user) => {
                if (err)
                    return done(err, false);
                else
                    return done(null, user);
            })
        }
    });
}
));


passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());