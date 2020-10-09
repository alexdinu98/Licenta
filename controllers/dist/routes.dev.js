"use strict";

var express = require('express');

var routes = express.Router();

var mongoose = require('mongoose');

var bodyparser = require('body-parser');

var bcrypt = require('bcryptjs');

var user = require('../models/usermodel');

var passport = require('passport');

var session = require('express-session');

var cookieParser = require('cookie-parser');

var flash = require('connect-flash');

require('./passport')(passport);

var crypto = require('crypto');

var multer = require('multer');

var GridFsStorage = require('multer-gridfs-storage');

var Grid = require('gridfs-stream');

var methodOverride = require('method-override');

var path = require('path'); // using Bodyparser for getting form data


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
routes.use(methodOverride('_method')); // Mongo URI

var mongoURI = 'mongodb+srv://alexdinu98:Azsxdcfvgb1@licenta.x0rth.gcp.mongodb.net/uploads?retryWrites=true&w=majority'; // Create mongo connection

var conn = mongoose.createConnection(mongoURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}); // Initgfs

var gfs;
conn.once('open', function () {
  //Init stream
  gfs = Grid(conn.db, mongoose.mongo);
  gfs.collection('uploads');
}); // Create storage engine

var storage = new GridFsStorage({
  url: mongoURI,
  file: function file(req, _file) {
    return new Promise(function (resolve, reject) {
      crypto.randomBytes(16, function (err, buf) {
        if (err) {
          return reject(err);
        }

        var filename = buf.toString('hex') + path.extname(_file.originalname);
        var fileInfo = {
          filename: filename,
          bucketName: 'uploads'
        };
        resolve(fileInfo);
      });
    });
  }
});
var upload = multer({
  storage: storage
}); // @route GET/
//@desc Loads form

routes.get('/success', checkAuthenticated, function (req, res) {
  gfs.files.find().toArray(function (err, files) {
    // Check if files
    if (!files || files.length === 0) {
      res.render('success', {
        files: false
      });
    } else {
      files.map(function (file) {
        if (file.contentType === 'image/png' || file.contentType === 'image/jpeg') {
          file.isImage = true;
        } else {
          file.isImage = false;
        }
      });
      res.render('success', {
        files: files
      });
    }
  });
}); //@route POST /upload
//@desc Uploads file to DB

routes.post('/upload', upload.single('file'), checkAuthenticated, function (req, res) {
  //res.json({file : req.file});
  res.redirect('/success');
}); // @route GET /files
// @desc Display all files in JSON

routes.get('/files', checkAuthenticated, function (req, res) {
  gfs.files.find().toArray(function (err, files) {
    // Check if files
    if (!files || files.length === 0) {
      return res.status(404).json({
        err: 'No files exist'
      });
    } // Files exist


    return res.json(files);
  });
}); // @route GET /files/:filename
// @desc Display single file object

routes.get('/files/:filename', checkAuthenticated, function (req, res) {
  gfs.files.findOne({
    filename: req.params.filename
  }, function (err, file) {
    // Check if file
    if (!file || file.length === 0) {
      return res.status(404).json({
        err: 'No file exist'
      });
    } //File exists


    return res.json(file);
  });
}); // @route GET /stl/:filename
// @desc Download the stl

routes.get('/stl/:filename', checkAuthenticated, function (req, res) {
  gfs.files.findOne({
    filename: req.params.filename
  }, function (err, file) {
    // Check if file
    if (!file || file.length === 0) {
      return res.status(404).json({
        err: 'No file exist'
      });
    } //Check if stl


    if (file.contentType === 'application/octet-stream') {
      // Read output to browser
      var readstream = gfs.createReadStream(file.filename);
      readstream.pipe(res);
    } else {
      res.status(404).json({
        err: 'Not an stl'
      });
    }
  });
}); // @route DELETE /files/:id
// @desc Delete file

routes["delete"]('/files/:id', checkAuthenticated, function (req, res) {
  gfs.remove({
    _id: req.params.id,
    root: 'uploads'
  }, function (err, gridStore) {
    if (err) {
      return res.status(404).json({
        err: err
      });
    }

    res.redirect('/success');
  });
});
module.exports = routes;