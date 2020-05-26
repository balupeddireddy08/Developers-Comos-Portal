//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const passport = require("passport");
const flash = require("connect-flash");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const session = require("express-session");
const passportLocalMongoose = require("passport-local-mongoose");
const findOrCreate = require("mongoose-findorcreate");
const app = express();
app.use(express.static("public"));
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({extended:true}));

app.use(session({
  secret:process.env.SECRET,
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

mongoose.connect("mongodb://localhost:27017/LoginDB",{useNewUrlParser:true,useUnifiedTopology:true});
mongoose.set("useCreateIndex",true);

const userSchema = new mongoose.Schema({
  name :String,
  email : String,
  password : String,
  googleId:String
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User = mongoose.model("user",userSchema);
passport.use(new LocalStrategy({usernameField:'email',passwordField:'password'},
  function(username, password, done) {
    User.findOne({ email: username }, function(err, user) {
      if (err) { return done(err); }
      if (!user) {
        return done(null, false, { message: 'Incorrect username.' });
      }
      bcrypt.compare(password, user.password, function(err, result) {

            if(result){
              return done(null,user);

            }
            else {
              return done(null, false, { message: 'Incorrect password.' });
            }
        });
    });
  }
));
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/welcome",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));



app.use(function(req, res, next) {
  res.locals.success_msg = req.flash('success_msg');
  res.locals.error_msg = req.flash('error_msg');
  res.locals.error = req.flash('error');
  next();
});
app.get("/",function(req,res){
  res.render("home");
});
app.get("/auth/google",passport.authenticate("google",{scope:["profile"]})
);
app.get("/auth/google/welcome",
  passport.authenticate("google",{failureRedirect:"/login"}),
  function(req,res){
    res.redirect("/welcome");
});

app.get("/login",function(req,res){
  res.render("login");
});
app.get("/register",function(req,res){
  res.render("register");
});
app.get("/welcome",function(req,res){
  res.render("welcome");
});
app.post("/register",function(req,res){
  const { name, email, password, password2 } = req.body;
  let errors = [];

  if (!name || !email || !password || !password2) {
    errors.push({ msg: 'Please enter all fields' });
  }

  if (password != password2) {
    errors.push({ msg: 'Passwords do not match' });
  }

  if (password.length < 6) {
    errors.push({ msg: 'Password must be at least 6 characters' });
  }

  if (errors.length > 0) {
    res.render('register', {
      errors,
      name,
      email,
      password,
      password2
    });
  } else {
    User.findOne({ email: email },function(err,user) {
      if (user) {
        errors.push({ msg: 'Email already exists' });
        res.render('register', {
          errors,
          name,
          email,
          password,
          password2
        });
      }
      else {
        const newUser = new User({
          name,
          email,
          password
        });

        bcrypt.genSalt(saltRounds, function(err, salt){
          bcrypt.hash(newUser.password, salt, function(err, hash) {
            if (err) throw err;
            newUser.password = hash;
            newUser.save();
            res.redirect('/welcome');

          });
        });
      }
    });
  }
});
app.post('/login',
  passport.authenticate('local', { successRedirect: '/welcome',
                                   failureRedirect: '/login',
                                   failureFlash: true })
);

app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/');
});
app.listen(3000,function(){
  console.log("Server has started on port 3000 succesfully");

});
