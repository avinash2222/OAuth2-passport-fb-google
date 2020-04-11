var express = require('express');
var router = express.Router();
const verify=require('../Authentication/verifyToken');
var UserController = require('../controllers/user');
const User = require('../models/user');
var passport = require('passport');
var authenticate = require('../Authentication/authenticate');

// login using passport-jwt
router.post('/login', passport.authenticate('local'), (req, res) => {

  var token = authenticate.getToken({_id: req.user._id});
  res.statusCode = 200;
  res.setHeader('Content-Type', 'application/json');
  res.json({success: true, token: token, status: 'You are successfully logged in!'});
});

// signup using passport-jwt
router.post('/signup', (req, res, next) => {
  User.register(new User({username: req.body.username}), 
    req.body.password, (err, user) => {
    if(err) {
      res.statusCode = 500;
      res.setHeader('Content-Type', 'application/json');
      res.json({err: err});
    }
    else {
      passport.authenticate('local')(req, res, () => {
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.json({success: true, status: 'Registration Successful!'});
      });
    }
  });
});

// facebook login
router.get('/facebook/token', passport.authenticate('facebook-token'), (req, res) => {
  if (req.user) {
    var token = authenticate.getToken({_id: req.user._id});
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.json({success: true, token: token, status: 'You are successfully logged in!'});
  }
});


// router.post('/register', User.hashPwd, UserController.createUser);

// Retrieve All users
router.get('/details', authenticate.verifyUser, UserController.findAll);

// Retrieve a single user with phoneNumber
router.get('/:_id', authenticate.verifyUser,  UserController.findOne);

// Update an user with phoneNumber
router.put('/:_id', verify.allowIfLoggedin,  UserController.update);

// Delete a user with phoneNumber
router.delete('/:_id', verify.allowIfLoggedin,  UserController.delete);


module.exports = router;
