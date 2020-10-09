const express = require('express');
const routes = express.Router();
const mongoose = require('mongoose');
const bodyparser = require('body-parser');
const bcrypt = require('bcryptjs');
const user = require('../models/usermodel');
const passport = require('passport');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const flash = require('connect-flash');
require('./passport')(passport);

const crypto = require('crypto');
const multer = require('multer');
const GridFsStorage = require('multer-gridfs-storage');
const Grid = require('gridfs-stream');
const methodOverride = require('method-override');
const path = require('path');


// using Bodyparser for getting form data
routes.use(bodyparser.urlencoded({ extended: true }));
// using cookie-parser and session 
routes.use(cookieParser('secret'));
routes.use(session({
    secret: 'secret',
    maxAge: 3600000,
    resave: true,
    saveUninitialized: true,
}));
// using passport for authentications 
routes.use(passport.initialize());
routes.use(passport.session());
// using flash for flash messages 
routes.use(flash());

// MIDDLEWARES
// Global variable
routes.use(function (req, res, next) {
    res.locals.success_message = req.flash('success_message');
    res.locals.error_message = req.flash('error_message');
    res.locals.error = req.flash('error');
    next();
});

const checkAuthenticated = function (req, res, next) {
    if (req.isAuthenticated()) {
        res.set('Cache-Control', 'no-cache, private, no-store, must-revalidate, post-check=0, pre-check=0');
        return next();
    } else {
        res.redirect('/login');
    }
}

// Connecting To Database
// using Mongo Atlas as database
mongoose.connect('mongodb+srv://alexdinu98:Azsxdcfvgb1@licenta.x0rth.gcp.mongodb.net/uploads?retryWrites=true&w=majority' ,{
    useNewUrlParser: true, useUnifiedTopology: true,
}).then(() => console.log("Database Connected")
);


// ALL THE ROUTES 
routes.get('/', (req, res) => {
    res.render('index');
})

routes.post('/register', (req, res) => {
    var { email, username, password, confirmpassword } = req.body;
    var err;
    if (!email || !username || !password || !confirmpassword) {
        err = "Please Fill All The Fields...";
        res.render('index', { 'err': err });
    }
    if (password != confirmpassword) {
        err = "Passwords Don't Match";
        res.render('index', { 'err': err, 'email': email, 'username': username });
    }
    if (typeof err == 'undefined') {
        user.findOne({ email: email }, function (err, data) {
            if (err) throw err;
            if (data) {
                console.log("User Exists");
                err = "User Already Exists With This Email...";
                res.render('index', { 'err': err, 'email': email, 'username': username });
            } else {
                bcrypt.genSalt(10, (err, salt) => {
                    if (err) throw err;
                    bcrypt.hash(password, salt, (err, hash) => {
                        if (err) throw err;
                        password = hash;
                        user({
                            email,
                            username,
                            password,
                        }).save((err, data) => {
                            if (err) throw err;
                            req.flash('success_message', "Registered Successfully.. Login To Continue..");
                            res.redirect('/login');
                        });
                    });
                });
            }
        });
    }
});


// Authentication Strategy
// ---------------


routes.get('/login', (req, res) => {
    res.render('login');
});

routes.post('/login', (req, res, next) => {
    passport.authenticate('local', {
        failureRedirect: '/login',
        successRedirect: '/success',
        failureFlash: true,
    })(req, res, next);
});


routes.use(methodOverride('_method'));

// Mongo URI
const mongoURI= 'mongodb+srv://alexdinu98:Azsxdcfvgb1@licenta.x0rth.gcp.mongodb.net/uploads?retryWrites=true&w=majority';

// Create mongo connection
const conn = mongoose.createConnection(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });

// Initgfs
let gfs;

conn.once('open', () => {
    //Init stream
    gfs = Grid(conn.db, mongoose.mongo);
    gfs.collection('uploads');
});

// Create storage engine
const storage = new GridFsStorage({
    url: mongoURI,
    file: (req, file) => {
      return new Promise((resolve, reject) => {
        crypto.randomBytes(16, (err, buf) => {
          if (err) {
            return reject(err);
          }
          const filename = buf.toString('hex') + path.extname(file.originalname);
          const fileInfo = {
            filename: filename,
            bucketName: 'uploads'
          };
          resolve(fileInfo);
        });
      });
    }
  });
  const upload = multer({ storage });

  // @route GET/
  //@desc Loads form
routes.get('/success',checkAuthenticated,(req, res) => {
    gfs.files.find().toArray((err, files) => {
        // Check if files
        if (!files || files.length === 0 ) {
            res.render('success', {files: false});
        } else {
            files.map(file => {
                if(file.contentType === 'image/png' || file.contentType === 'image/jpeg' ) {
                    file.isImage = true;
                } else {
                    file.isImage = false;
                }
            });
            res.render('success', {files: files});
        }
    });
});

//@route POST /upload
//@desc Uploads file to DB
routes.post('/upload', upload.single('file'),checkAuthenticated , (req, res) => {
    //res.json({file : req.file});
    res.redirect('/success');
});

// @route GET /files
// @desc Display all files in JSON
routes.get('/files',checkAuthenticated, (req, res) => {
    gfs.files.find().toArray((err, files) => {
        // Check if files
        if (!files || files.length === 0 ) {
            return res.status(404).json({
                err: 'No files exist'
            });
        }

        // Files exist
        return res.json(files);
    });
});

// @route GET /files/:filename
// @desc Display single file object
routes.get('/files/:filename',checkAuthenticated, (req, res) => {
    gfs.files.findOne({filename: req.params.filename}, (err, file) => {
    // Check if file
    if (!file || file.length === 0 ) {
        return res.status(404).json({
            err: 'No file exist'
        });
    }
    //File exists
    return res.json(file);
});
});

// @route GET /stl/:filename
// @desc Download the stl
routes.get('/stl/:filename',checkAuthenticated, (req, res) => {
    gfs.files.findOne({filename: req.params.filename}, (err, file) => {
    // Check if file
    if (!file || file.length === 0 ) {
        return res.status(404).json({
            err: 'No file exist'
        });
    }
    
        // Read output to browser
        const readstream = gfs.createReadStream(file.filename);
        readstream.pipe(res);
    
});
});

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

var os = require('os');
var chilkat = require('@chilkat/ck-node12-linux64'); 
// @route GET /print/:filename
// @desc print the stl
routes.get('/print/:filename',checkAuthenticated, (req, res) => {

    gfs.files.findOne({filename: req.params.filename}, (err, file) => {
        // Check if file
        if (!file || file.length === 0 ) {
            return res.status(404).json({
                err: 'No file exist'
            });
        }
        //Check if stl
        if(file.contentType === 'application/octet-stream' ){
            // Read output to browser
            var fs = require('fs');
            let data = [];
            let readstream = gfs.createReadStream(file.filename);
            var stream = fs.createWriteStream('stl/someFile.stl', {flags: 'w'});
            readstream.on('data', function(chunk) {
                stream.write(chunk);
            });
            readstream.on('end', function () {
               data = Buffer.concat(data);
            });
            //readstream.pipe(res);
        } else{
            res.status(404).json({
                err: 'Not an stl'
            })
        }
    });
    sleep(2000).then(() => {
    // This example assumes Chilkat SSH/SFTP to have been previously unlocked.
    // See Unlock SSH for sample code.

    var ssh = new chilkat.Ssh();
    var sftp = new chilkat.SFtp();

    // Set some timeouts, in milliseconds:
    sftp.ConnectTimeoutMs = 5000;
    sftp.IdleTimeoutMs = 10000;

    var port = 10022;
    var success = ssh.Connect("raspberry-pi-dinu.go.ro",port);
    if (success !== true) {
        console.log(ssh.LastErrorText);
        return;
    }

    // Authenticate using login/password:
    success = ssh.AuthenticatePw("ubuntu","alex123");
    if (success !== true) {
        console.log(ssh.LastErrorText);
        return;
    }

    var success = sftp.Connect("raspberry-pi-dinu.go.ro",port);
    if (success !== true) {
        console.log(sftp.LastErrorText);
        return;
    }

    // Authenticate with the SSH server.  Chilkat SFTP supports
    // both password-based authenication as well as public-key
    // authentication.  This example uses password authenication.
    success = sftp.AuthenticatePw("ubuntu","alex123");
    if (success !== true) {
        console.log(sftp.LastErrorText);
        return;
    }

    // After authenticating, the SFTP subsystem must be initialized:
    success = sftp.InitializeSftp();
    if (success !== true) {
        console.log(sftp.LastErrorText);
        return;
    }

    // Open a file for writing on the SSH server.
    // If the file already exists, it is overwritten.
    // (Specify "createNew" instead of "createTruncate" to
    // prevent overwriting existing files.)
    var handle = sftp.OpenFile("stl/print.stl","writeOnly","createTruncate");
    if (sftp.LastMethodSuccess !== true) {
        console.log(sftp.LastErrorText);
        return;
    }

    // Upload from the local file to the SSH server.
    success = sftp.UploadFile(handle,"stl/someFile.stl");
    if (success !== true) {
        console.log(sftp.LastErrorText);
        return;
    }

    // Close the file.
    success = sftp.CloseHandle(handle);
    if (success !== true) {
        console.log(sftp.LastErrorText);
        return;
    }

    // Start a shell session.
    // (The QuickShell method was added in Chilkat v9.5.0.65)
    var channelNum = ssh.QuickShell();
    if (channelNum < 0) {
        console.log(ssh.LastErrorText);
        return;
    }
    ssh.ReadTimeoutMs = 1000;
    // Construct a StringBuilder with multiple commands, one per line.
    // Note: The line-endings are potentially important.  Some SSH servers may
    // require either LF or CRLF line endings.  (Unix/Linux/OSX servers typically
    // use bare-LF line endings.  Windows servers likely use CRLF line endings.)
    var sbCommands = new chilkat.StringBuilder();
    
    //Make Gcode 
    sbCommands.Append("CuraEngine slice -v -p -j /opt/curaengine/fdmprinter.def.json -o /home/ubuntu/gcode/print.gcode -l /home/ubuntu/stl/print.stl\n");
    success = ssh.ChannelSendString(channelNum,sbCommands.GetAsString(),"ansi");sbCommands.Clear();
    console.log("--- output ----");
    console.log(ssh.GetReceivedText(channelNum,"ansi"));
    sbCommands.Append("systemctl is-active print.service\n");
    success = ssh.ChannelSendString(channelNum,sbCommands.GetAsString(),"ansi");sbCommands.Clear();
    var checkactive = ssh.ChannelReceiveUntilMatch(channelNum,"\nactive","ansi",false);
    var checkinactive = ssh.ChannelReceiveUntilMatch(channelNum,"\ninactive","ansi",false);
    var checkfailed = ssh.ChannelReceiveUntilMatch(channelNum,"\nfailed","ansi",false);
    if(checkinactive === true){
        sbCommands.Append("sudo systemctl start print.service\n");
    } else if(checkactive === true) {
            sbCommands.Append("echo Printer Bussy\n");
        } else if(checkfailed === true) {
                 sbCommands.Append("echo Service Failed, Try to restart service\n");
                 sbCommands.Append("sudo systemctl start print.service\n");
                } else {
                    sbCommands.Append("echo ERROR Unknown \necho Check Logs\n\n");
                }
    success = ssh.ChannelSendString(channelNum,sbCommands.GetAsString(),"ansi");sbCommands.Clear();
    console.log(ssh.GetReceivedText(channelNum,"ansi"));
    var sleep=ssh.ChannelReceiveUntilMatch(channelNum,"sleep:)","ansi",false);
    sbCommands.Append("systemctl is-active print.service\n");
    success = ssh.ChannelSendString(channelNum,sbCommands.GetAsString(),"ansi");sbCommands.Clear();
    var checkactive = ssh.ChannelReceiveUntilMatch(channelNum,"\nactive","ansi",false);
    var checkfailed = ssh.ChannelReceiveUntilMatch(channelNum,"\nfailed","ansi",false);
    if(checkactive === true){
        sbCommands.Append("echo Print Started\n");
    } else if(checkfailed === true) {
                 sbCommands.Append("echo Printer is DEAD\n");
                } else {
                    sbCommands.Append("echo ERROR Unknown \nCheck Logs\n\n");
                }        
    // For our last command, we're going to echo a marker string that
    // we'll use in ChannelReceiveUntilMatch below.
    // The use of single quotes around 'IS' is a trick so that the output
    // of the command is "THIS IS THE END OF THE SCRIPT", but the terminal echo
    // includes the single quotes.  This allows us to read until we see the actual
    // output of the last command.
    //sbCommands.Append("echo THIS 'IS' THE END OF THE SCRIPT\n");
    sbCommands.Append("exit\n");
    

    // Send the commands..
    success = ssh.ChannelSendString(channelNum,sbCommands.GetAsString(),"ansi");
    if (success !== true) {
        console.log(ssh.LastErrorText);
        return;
    }

    // Send an EOF to indicate no more commands will be sent.
    // For brevity, we're not checking the return values of each method call.
    // Your code should check the success/failure of each call.
    success = ssh.ChannelSendEof(channelNum);

    // Receive output up to our marker.
    success = ssh.ChannelReceiveUntilMatch(channelNum,"logout","ansi",true);

    // Close the channel.
    // It is important to close the channel only after receiving the desired output.
    success = ssh.ChannelSendClose(channelNum);

    // Get any remaining output..
    success = ssh.ChannelReceiveToClose(channelNum);

    // Get the complete output for all the commands in the session.
    console.log(ssh.GetReceivedText(channelNum,"ansi"));

    res.redirect('/success');
});
});



// @route DELETE /files/:id
// @desc Delete file
routes.delete('/files/:id',checkAuthenticated, (req,res) => {
    gfs.remove({_id: req.params.id, root: 'uploads'}, (err, gridStore) => {
        if(err) {
            return res.status(404).json({err: err})
        }

        res.redirect('/success');
    });
});

module.exports = routes;
