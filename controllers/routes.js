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

// Linkul catre baza de date
const mongoURI= 'mongodb+srv://alexdinu98:Azsxdcfvgb1@licenta.x0rth.gcp.mongodb.net/uploads?retryWrites=true&w=majority';

// Conexinuea mongo pentru baza de date
const conn = mongoose.createConnection(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });

// Initializez gridfs
let gfs;

conn.once('open', () => {
    //Initializez stream-ul de date 
    gfs = Grid(conn.db, mongoose.mongo);
    gfs.collection('uploads');
});

// Creez storage engine-ul
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

// "Bodyparser" preia datele din formularul de inregistrare
routes.use(bodyparser.urlencoded({ extended: true }));
routes.use(cookieParser('secret'));
routes.use(session({
    secret: 'secret',
    maxAge: 3600000,
    resave: true,
    saveUninitialized: true,
}));
// Utilizez "passport" pentru autentificare
routes.use(passport.initialize());
routes.use(passport.session());
// Utilizez "flash" pentru afisarea mesajelor 
routes.use(flash());


routes.use(function (req, res, next) {
    res.locals.success_message = req.flash('success_message');
    res.locals.error_message = req.flash('error_message');
    res.locals.error = req.flash('error');
    next();
});

// Am creat o functie sa verifice daca userul este autentificat
const checkAuthenticated = function (req, res, next) {
    if (req.isAuthenticated()) {
        res.set('Cache-Control', 'no-cache, private, no-store, must-revalidate, post-check=0, pre-check=0');
        return next();
    } else {
        res.redirect('/login');
    }
}

// Se creaza conexiunea la baza de date
// folosind Mongo Atlas (baza de date in cloud)
mongoose.connect('mongodb+srv://alexdinu98:Azsxdcfvgb1@licenta.x0rth.gcp.mongodb.net/uploads?retryWrites=true&w=majority' ,{
    useNewUrlParser: true, useUnifiedTopology: true,
}).then(() => console.log("Database Connected")
);


// Route-urile folosite

//Metoda de suprascriere pentru stergerea unui fisier
routes.use(methodOverride('_method'));

routes.get('/', (req, res) => {
    res.render('index');
})

// Strategia de autentificare
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

// @route POST/register
//@desc Route pentru inregistrarea unui nou utilizator
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

//@route GET/
//@desc Route pentru pagina de print
routes.get('/success',checkAuthenticated,(req, res) => {
    gfs.files.find().toArray((err, files) => {
        // Verifica daca exista vreun fisier in baza de date
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
//@desc Incarca fisierul in baza de date
routes.post('/upload', upload.single('file'),checkAuthenticated , (req, res) => {
    res.redirect('/success');
});

// @route GET /stl/:filename
// @desc Descarca fisierul stl in device-ul utilizatorului
routes.get('/stl/:filename',checkAuthenticated, (req, res) => {
    gfs.files.findOne({filename: req.params.filename}, (err, file) => {
    // Verifica daca exista vreun fisier in baza de date
    if (!file || file.length === 0 ) {
        return res.status(404).json({
            err: 'No file exist'
        });
    }
    const readstream = gfs.createReadStream(file.filename);
    readstream.pipe(res);
    
});
});

// @desc Am creat aceasta functie pentru a intarzia comenzile SFTP si SSH,
// pentru ca download-ul fisierului si transferul acestuia sa aiba loc
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

var os = require('os');
var chilkat = require('@chilkat/ck-node12-win64'); 
// @route GET /print/:filename
// @desc print the stl
routes.get('/print/:filename',checkAuthenticated, (req, res) => {

    gfs.files.findOne({filename: req.params.filename}, (err, file) => {
        // Verifica daca exista vreun fisier in baza de date
        if (!file || file.length === 0 ) {
            return res.status(404).json({
                err: 'No file exist'
            });
        }
        // Verifica daca fisierul este de tip stl si il descarca in folderul /stl din server
        if(file.contentType === 'application/octet-stream' ){
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
        } else{
            res.status(404).json({
                err: 'Not an stl'
            })
        }
    });
    sleep(2000).then(() => {

    
    var ssh = new chilkat.Ssh();
    var sftp = new chilkat.SFtp();

    sftp.ConnectTimeoutMs = 5000;
    sftp.IdleTimeoutMs = 10000;

    var port = 10022;
    
    // Deschide conexiunea SFTP si SSH din serverul NodeJS catre RaspberryPi
    var success = ssh.Connect("raspberry-pi-dinu.go.ro",port);
    if (success !== true) {
        console.log(ssh.LastErrorText);
        return;
    }
    var success = sftp.Connect("raspberry-pi-dinu.go.ro",port);
    if (success !== true) {
        console.log(sftp.LastErrorText);
        return;
    }

    // Autentificarea SSH si SFTP catre RaspberryPi
    success = ssh.AuthenticatePw("ubuntu","alex123");
    if (success !== true) {
        console.log(ssh.LastErrorText);
        return;
    }
    success = sftp.AuthenticatePw("ubuntu","alex123");
    if (success !== true) {
        console.log(sftp.LastErrorText);
        return;
    }

    // Initializare SFTP
    success = sftp.InitializeSftp();
    if (success !== true) {
        console.log(sftp.LastErrorText);
        return;
    }

    
    // Deschide un fisier pentru scriere
    // Daca aceesta deja exista, el va fi rescris
    var handle = sftp.OpenFile("stl/print.stl","writeOnly","createTruncate");
    if (sftp.LastMethodSuccess !== true) {
        console.log(sftp.LastErrorText);
        return;
    }

    // Uploadeaza fiserul din serveru de NodeJS in folderul /stl din RaspberryPi
    success = sftp.UploadFile(handle,"stl/someFile.stl");
    if (success !== true) {
        console.log(sftp.LastErrorText);
        return;
    }

    // Inchide fisierul
    success = sftp.CloseHandle(handle);
    if (success !== true) {
        console.log(sftp.LastErrorText);
        return;
    }

    // Porneste sesiunea shell
    var channelNum = ssh.QuickShell();
    if (channelNum < 0) {
        console.log(ssh.LastErrorText);
        return;
    }
    ssh.ReadTimeoutMs = 1000;
    var sbCommands = new chilkat.StringBuilder();
    
    /*
    Acesta este scriptul Python care citeste si trimite comenzile linie cu linie catre imprimanta 3d,
    Scriptul este transformat in service, utilizatorul nefiind obligat sa tina browserul deschis
    pe perioada printarii

    import serial
    import sys
    import time

    #reads the gcode file
    gcodeFile = open('/home/ubuntu/example.gcode','r')
    gcode = gcodeFile.readlines()

    #connects to the printer
    printer = serial.Serial('/dev/ttyUSB0',115200)

    #executes each line of the gcode
    for line in gcode:
    response = ''
    #removes comments
    line = line.split(";")[0]
    #makes sure line is a valid command
    if(line != "" and line != "\n"):
        print("line: "+line)
        #writes the gcode to the printer
        printer.write(str.encode(line+'\n'))
        #waits for OK response from printer
        while response.count("ok") == 0:
            #waits for response
            while printer.in_waiting == 0:
                time.sleep(0.01)
            response = ''
            #gets response info
            while printer.in_waiting > 0:
                response += str(printer.readline())
            print(response)*/

    //Transforma fisierul stl in gcode cu ajutorul CuraEngine
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
    sbCommands.Append("exit\n");
    

    // Trimite toate comenzile SSH
    success = ssh.ChannelSendString(channelNum,sbCommands.GetAsString(),"ansi");
    if (success !== true) {
        console.log(ssh.LastErrorText);
        return;
    }

 
    success = ssh.ChannelSendEof(channelNum);

    success = ssh.ChannelReceiveUntilMatch(channelNum,"logout","ansi",true);

    success = ssh.ChannelSendClose(channelNum);

    success = ssh.ChannelReceiveToClose(channelNum);

    console.log(ssh.GetReceivedText(channelNum,"ansi"));

    res.redirect('/success');
});
});



// @route DELETE /files/:id
// @desc Sterge un fisier stl
routes.delete('/files/:id',checkAuthenticated, (req,res) => {
    gfs.remove({_id: req.params.id, root: 'uploads'}, (err, gridStore) => {
        if(err) {
            return res.status(404).json({err: err})
        }

        res.redirect('/success');
    });
});

module.exports = routes;
