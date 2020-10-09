"use strict";

var express = require('express');

var routes = express.Router();

var mongoose = require('mongoose');

var bodyparser = require('body-parser');

var bcrypt = require('bcryptjs');

var user = require('./models.js');

var passport = require('passport');

var session = require('express-session');

var cookieParser = require('cookie-parser');

var flash = require('connect-flash'); //const mongourl = require('./config/mongokey');
// using Bodyparser for getting form data


routes.use(bodyparser.urlencoded({
  extended: true
})); // using cookie-parser and session 

routes.use(cookieParser('secret'));
routes.use(session({
  secret: 'secret',
  maxAge: 3600000,
  resave: true,
  saveUninitialized: true
})); // using passport for authentications 

routes.use(passport.initialize());
routes.use(passport.session()); // using flash for flash messages 

routes.use(flash()); // MIDDLEWARES
// Global variable

routes.use(function (req, res, next) {
  res.locals.success_message = req.flash('success_message');
  res.locals.error_message = req.flash('error_message');
  res.locals.error = req.flash('error');
  next();
});

var checkAuthenticated = function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    res.set('Cache-Control', 'no-cache, private, no-store, must-revalidate, post-check=0, pre-check=0');
    return next();
  } else {
    res.redirect('/login');
  }
}; // Connecting To Database
// using Mongo Atlas as database


mongoose.connect('mongodb+srv://alexdinu98:Azsxdcfvgb1@licenta.x0rth.gcp.mongodb.net/uploads?retryWrites=true&w=majority', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(function () {
  return console.log("Database Connected");
}); // ALL THE ROUTES 

routes.get('/', function (req, res) {
  res.render('index');
});
routes.post('/register', function (req, res) {
  var _req$body = req.body,
      email = _req$body.email,
      username = _req$body.username,
      password = _req$body.password,
      confirmpassword = _req$body.confirmpassword;
  var err;

  if (!email || !username || !password || !confirmpassword) {
    err = "Please Fill All The Fields...";
    res.render('index', {
      'err': err
    });
  }

  if (password != confirmpassword) {
    err = "Passwords Don't Match";
    res.render('index', {
      'err': err,
      'email': email,
      'username': username
    });
  }

  if (typeof err == 'undefined') {
    user.findOne({
      email: email
    }, function (err, data) {
      if (err) throw err;

      if (data) {
        console.log("User Exists");
        err = "User Already Exists With This Email...";
        res.render('index', {
          'err': err,
          'email': email,
          'username': username
        });
      } else {
        bcrypt.genSalt(10, function (err, salt) {
          if (err) throw err;
          bcrypt.hash(password, salt, function (err, hash) {
            if (err) throw err;
            password = hash;
            user({
              email: email,
              username: username,
              password: password
            }).save(function (err, data) {
              if (err) throw err;
              req.flash('success_message', "Registered Successfully.. Login To Continue..");
              res.redirect('/login');
            });
          });
        });
      }
    });
  }
}); // Authentication Strategy
// ---------------

var localStrategy = require('passport-local').Strategy;

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
}); // ---------------
// end of autentication statregy

routes.get('/login', function (req, res) {
  res.render('login');
});
routes.post('/login', function (req, res, next) {
  passport.authenticate('local', {
    failureRedirect: '/login',
    successRedirect: '/success',
    failureFlash: true
  })(req, res, next);
});
routes.get('/success', checkAuthenticated, function (req, res) {
  res.render('success', {
    'user': req.user
  });
});
routes.get('/logout', function (req, res) {
  req.logout();
  res.redirect('/login');
});
routes.post('/addmsg', checkAuthenticated, function (req, res) {
  user.findOneAndUpdate({
    email: req.user.email
  }, {
    $push: {
      messages: req.body['msg']
    }
  }, function (err, suc) {
    if (err) throw err;
    if (suc) console.log("Added Successfully...");
  });
  res.redirect('/success');
});
module.exports = routes;