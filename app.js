//jshint esversion:6
require('dotenv').config();
const express = require('express');
const http = require('http');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
// const encrypt = require('mongoose-encryption');

// LEVEL 3 hash password
const md5 = require("md5");

// LEVEL 4 add cookies and sessions (to stay login after changing page)
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

// LEVEL 6 oauth-google
// const GoogleStrategy = require("passport-google-oauth20").Strategy;
const GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
const findOrCreate = require('mongoose-findorcreate');


const app = express();


app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

// LEVEL 4
app.use(session({
    secret: "This is ou little secret.",
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());



//CONNECTION
mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true});
// LEVEL 4 connection
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

// LEVEL 4
userSchema.plugin(passportLocalMongoose);
// LEVEL 6
userSchema.plugin(findOrCreate);


//LEVEL 2 DATA ENCRYPTION
// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ['password'] });
const User = new mongoose.model("User", userSchema);

// LEVEL 4
passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser(function(user, done) {
    done(null, user.id);
}));
passport.deserializeUser(User.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
}));


// LEVEL 6
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
function(accessToken, refreshToken, profile, done) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, 
        function (err, user) {
            return done(err, user);
    });
    }
));



//TODO
app.get('/', function(req, res) {
    res.render('home');
});

// LEVEL 6
app.get('/auth/google', 
    passport.authenticate('google', { scope: ['profile'] })
);
app.get("/auth/google/secrets", 
    passport.authenticate('google', { failureRedirect: "/login" }),
    function(req, res) {
        // successful authenticated redirect
        res.redirect("/");
});

app.get('/login', function(req, res) {
    res.render('login');
});

app.get('/register', function(req, res) {
    res.render('register');
});

app.get("/secrets" ,function(req, res) {
    User.find({ "secret": {$ne:null}}, function(err, foundUsers) {
        if (err) {
            console.log(err);
        } else {
            if (foundUsers) {
                res.render("secrets", {usersWithSecrets: foundUsers});
            }
        }
    });
});

app.get('/submit', function(req, res) {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.post("/submit", function(req, res) {
    const submittingSecret = req.body.secret;
    User.findById(req.user.id, function(err, foundUser) {
        if (err) {
            console.log(err);
        } else {
            if (foundUser) {
                foundUser.secret = submittingSecret;
                foundUser.save(function() {
                    res.redirect("/secrets");
                });
            }
        }
    });
});

app.get('/logout', function(req, res) {
    req.logout();
    res.redirect("/");
});

app.post("/register", function(req, res) {
    // LEVEL 3

    // const newUser = new User({
    //     email: req.body.username,
    //     password: md5(req.body.password)
    // });
    // newUser.save(function(err) {
    //     if(err) {
    //         console.log(err);
    //     } else {
    //         res.render("secrets");
    //     }
    // });

    // LEVEL 4
    User.register({username: req.body.username}, req.body.password, function(err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/login", function(req, res) {
    // LEVEL 3

    // const username =  req.body.username;
    // const password = md5(req.body.password);
    // User.findOne({email:username}, function(err, foundUser) {
    //     if (err) {
    //         console.log(err);
    //     } else {
    //         if (foundUser){
    //             if (foundUser.password === password) {
    //                 res.render("secrets");
    //             }
    //         }
    //     }
    // });

    //LEVEL 4
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    req.login(user, function(err) {
        if(err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
            });
        }
    });
});











app.listen(3000, function() {
    console.log("Running on port 3000...");
});