//jshint esversion:6
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const passport = require("passport");
const LocalStrategy = require('passport-local').Strategy;
const session = require("express-session");
const passportLocalMongoose = require("passport-local-mongoose");
const findOrCreate = require("mongoose-findorcreate");
const app = express();

app.use(express.static("public"));
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({extended:true}));

app.use(session({
  secret:"Thisisnotmysecret",
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
mongoose.connect("mongodb://localhost:27017/LoginDB",{useNewUrlParser:true,useUnifiedTopology:true});
mongoose.set("useCreateIndex",true);

const userSchema = new mongoose.Schema({
  email : String,
  password : String
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User = mongoose.model("user",userSchema);


passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

app.get("/welcome",function(req,res){
  if(req.isAuthenticated()){
  res.render("welcome");
}else{

  res.redirect("/login");
}
});
app.get("/logout",function(req,res){
  req.logout();
  res.redirect("/");
});
app.get("/",function(req,res){
  res.render("home");
});
app.get("/register",function(req,res){
  res.render("register");
});

app.get("/login",function(req,res){
  res.render("login");
});

app.post("/register",function(req,res){
  User.register({username:req.body.username},req.body.password,function(err,user){
    if(err){
      console.log(err);
      res.redirect("/register");
    }else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/welcome");
      });
    }
  });
});
app.post('/login',
  passport.authenticate('local', { successRedirect: "/welcome",
                                   failureRedirect: "/login" }));




app.listen(3000,function(){
  console.log("Server has started on port 3000 succesfully");

});
