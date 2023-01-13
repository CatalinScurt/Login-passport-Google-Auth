require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
// const encrypt = require("mongoose-encryption");   //for encrypting with secret key
// const md5 = require("md5"); // for only hash
// const bcrypt = require("bcrypt");
// const saltRounds = 10;
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
    secret: "Our little secre.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");
// , { useNewUrlParser: true }

const secretSchema = new mongoose.Schema({
    content: String,
    author: String
});

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: [secretSchema]
});

// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] }); ////for encrypting with secret key

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const Secret = mongoose.model("Secret", secretSchema);
const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
    (accessToken, refreshToken, profile, cb) => {
        console.log(profile);

        User.findOrCreate({ googleId: profile.id }, (err, user) => {
            return cb(err, user);
        });
    }
));

app.get("/", (req, res) => {
    res.render("home");
});

app.get("/auth/google", passport.authenticate("google", {
    scope: ['profile']
}));

app.get("/auth/google/secrets",
    passport.authenticate('google', { failureRedirect: '/login', failureMessage: true }),
    function (req, res) {
        res.redirect("/secrets");
    });

app.get("/login", (req, res) => {
    console.log(req.session.messages);
    res.render("login", { errorMessage: req.session.messages });
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.get("/secrets", (req, res) => {
    if (req.isAuthenticated()) {
        User.find({ $and: [{ "secret": { $ne: [] } }, { "secret": { $ne: null } }] }, (err, foundUsers) => {
            if (err) {
                console.log(err);
            } else {
                if (foundUsers) {
                    console.log(foundUsers)
                    res.render("secrets", { userWithSecrets: foundUsers });
                }
            }
        });
    } else {
        res.render("login", { errorMessage: "You must log in to continue" });
    }

});

app.get("/submit", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.post("/submit", (req, res) => {
    const submittedSecret = req.body.secret;
    User.findById(req.user.id, (err, foundUser) => {
        if (err) {
            console.log(err);
        } else {
            if (foundUser) {
                const newSecret = new Secret({
                    content: submittedSecret,
                    author: req.user.id
                });
                newSecret.save();
                // foundUser.secret = submittedSecret;
                foundUser.secret.push(newSecret);
                foundUser.save(() => {
                    res.redirect("/secrets")
                });
            }
        }
    });
});

app.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) {
            console.log(err);
        }
    });
    res.redirect("/");
});

app.post("/register", (req, res) => {

    // bcrypt.hash(req.body.password, saltRounds, (err, hash) => {

    //     const newUser = new User({
    //         email: req.body.username,
    //         password: hash
    //     });
    //     newUser.save((err) => {
    //         if (err) {
    //             console.log(err);
    //         } else {
    //             res.render('secrets');
    //         }
    //     });
    // });

    User.register({ username: req.body.username }, req.body.password, (err, user) => {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            });
        }
    });

});

app.post("/login", (req, res) => {
    // const userName = req.body.username;
    // const password = req.body.password;
    // User.findOne({ email: userName }, (err, foundUser) => {
    //     if (err) {
    //         console.log(err);
    //     } else {
    //         if (foundUser) {
    //             bcrypt.compare(password, foundUser.password, (err, result) => {
    //                 if (result === true) {
    //                     res.render("secrets");
    //                 }
    //             });
    //         }
    //     }
    // });

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, (err) => {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local", { failureRedirect: "/login", failureMessage: true })(req, res, () => {
                res.redirect("/secrets");
            });
        }
    });
});




app.listen(3000, function () {
    console.log("Server started on port 3000");
});

