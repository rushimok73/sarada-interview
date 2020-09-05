if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config()
}

const express = require('express')
const app = express()
const bcrypt = require('bcrypt')
const passport = require('passport')
const flash = require('express-flash')
const session = require('express-session')
const methodOverride = require('method-override')
const async = require("async");
const nodemailer = require("nodemailer");
const crypto = require("crypto");

const initializePassport = require('./passport-config')
initializePassport(
  passport,
  email => users.find(user => user.email === email),
  id => users.find(user => user.id === id)
)

const users = []

app.set('view-engine', 'ejs')
app.use(express.urlencoded({ extended: false }))
app.use(express.static('public'))
app.use(flash())
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}))
app.use(passport.initialize())
app.use(passport.session())
app.use(methodOverride('_method'))

app.get('/', checkAuthenticated, (req, res) => {
  res.render('index.ejs', { name: req.user.name })
})

app.get('/login', checkNotAuthenticated, (req, res) => {
  res.render('login.ejs')
})

app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login',
  failureFlash: true,
  successFlash: 'Successfully logged in!'
}))

app.get('/register', checkNotAuthenticated, (req, res) => {
  res.render('register.ejs')
})

app.post('/register', checkNotAuthenticated, async (req, res) => {
  var myerrors = [];
  var target = users.find(function (element) {
        return element.email == req.body.email;
  })
  if(target!=null){
    myerrors.push({msg: 'Email already exists'})
    res.render('register.ejs', {myerrors: myerrors})
  }else if(req.body.password.length<6){
    myerrors.push({msg: 'Password length should contain more than 6 characters'})
    res.render('register.ejs', {myerrors: myerrors})
  }else{
    try {
      const hashedPassword = await bcrypt.hash(req.body.password, 10)
      users.push({
        id: Date.now().toString(),
        name: req.body.name,
        email: req.body.email,
        password: hashedPassword
      })
      myerrors.push({msg: 'Successfully registered!'})
      res.render('login.ejs', {myerrors: myerrors})
    } catch {
      res.redirect('/register')
    }
  }
})

app.delete('/logout', (req, res) => {
  console.log("logout request recieved")
  req.logOut()
  res.redirect('/login')
})

// forgot password
app.get('/forgot', function(req, res) {
  res.render('forgot.ejs');
});

app.post('/forgot', function(req, res, next) {
  async.waterfall([
    function(done) {
      crypto.randomBytes(20, function(err, buf) {
        var token = buf.toString('hex');
        done(err, token);
      });
    },
    function(token, done) {
      var target = users.find(function (element) {
            return element.email == req.body.email;
      })
      if(!target){
        console.log("No user with email id found")
      }else{
        target.resetPasswordToken = token;
        target.resetPasswordExpires = Date.now() + 3600000;
        var err = null;
        done(err,token,target);
      }
    },
    function(token, target, done) {
      var smtpTransport = nodemailer.createTransport({
        service: 'Gmail',
        auth: {
          user: 'pjordanx@gmail.com',
          pass: process.env.GMAILPW
        }
      });
      var mailOptions = {
        to: target.email,
        from: 'pjordanx@gmail.com',
        subject: 'Node.js Password Reset',
        text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
          'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
          'http://localhost:3000' + '/reset/' + token + '\n\n' +
          'If you did not request this, please ignore this email and your password will remain unchanged.\n'
      };
      smtpTransport.sendMail(mailOptions, function(err) {
        console.log('mail sent');
        req.flash('success', 'An e-mail has been sent to ' + target.email + ' with further instructions.');
        done(err, 'done');
      });
    }
  ], function(err) {
    if (err) return next(err);
    let myerrors = [];
    myerrors.push({msg : 'Email Sent. Check your inbox!'})
    res.render('forgot.ejs', {myerrors: myerrors});
  });
});

app.get('/reset/:token', function(req, res) {
  var target = users.find(function (element) {
        return element.resetPasswordToken == req.params.token;
  })
  if(!target){
    console.log("invalid token")
    return res.redirect('/forgot');
  }else{
    var stillvalid;
    if(target.resetPasswordExpires >= Date.now()){
      console.log("Token still not expired");
      res.render('reset.ejs', {token: req.params.token});
    }else{
      console.log("Token expired");
    }
  }
});

app.post('/reset/:token', function(req, res) {
  async.waterfall([
    async function(done) {
      var target = users.find(function (element) {
            return element.resetPasswordToken == req.params.token;
      })
      if(req.body.password === req.body.confirm) {
        const hashedPassword = await bcrypt.hash(req.body.password, 10)
        target.password = hashedPassword;
        console.log(hashedPassword);
        console.log(req.body.password);
        var err = null;
        done(err,target);
      } else {
          req.flash("error", "Passwords do not match.");
          return res.redirect('back');
      }
    },
    function(target, done) {
      var smtpTransport = nodemailer.createTransport({
        service: 'Gmail',
        auth: {
          user: 'pjordanx@gmail.com',
          pass: process.env.GMAILPW
        }
      });
      var mailOptions = {
        to: target.email,
        from: 'pjordanx@mail.com',
        subject: 'Your password has been changed',
        text: 'Hello,\n\n' +
          'This is a confirmation that the password for your account ' + target.email + ' has just been changed.\n'
      };
      smtpTransport.sendMail(mailOptions, function(err) {
        req.flash('success', 'Success! Your password has been changed.');
        done(err);
      });
    }
  ], function(err) {
    res.redirect('/login');
  });
});


function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next()
  }

  res.redirect('/login')
}

function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect('/')
  }
  next()
}

app.listen(3000)
