"use strict";

var localStrategy = require('passport-local').Strategy;

var user = require('../models/usermodel');

var bcrypt = require('bcryptjs');

module.exports = function (passport) {
  passport.use(new localStrategy({
    usernameField: 'email'
  }, function (email, password, done) {
    user.findOne({
      email: email
    }, function (err, data) {
      if (err) throw err;

      if (!data) {
        return done(null, false, {
          message: "User Doesn't Exists.."
        });
      }

      bcrypt.compare(password, data.password, function (err, match) {
        if (err) {
          return done(null, false);
        }

        if (!match) {
          return done(null, false, {
            message: "Password Doesn't Match"
          });
        }

        if (match) {
          return done(null, data);
        }
      });
    });
  }));
  passport.serializeUser(function (user, cb) {
    cb(null, user.id);
  });
  passport.deserializeUser(function (id, cb) {
    user.findById(id, function (err, user) {
      cb(err, user);
    });
  });
};