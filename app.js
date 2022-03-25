//jshint esversion:6
//level3
//create .env file
require('dotenv').config()
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const findOrCreate = require('mongoose-findorcreate')
//level2
// var encrypt = require('mongoose-encryption');
// const md5 = require("md5")
// const bcrypt = require("bcrypt")
// //we define no of salt round- when hashing passing through it - it changes everytime to prevent from hacking
// const saltRounds = 10;
const session = require('express-session')
const passport = require("passport")
const passportLocalMongoose = require("passport-local-mongoose");

const app = express();

//refer documentaion .env 
// console.log(process.env.API_KEY);


// console.log(md5('12345'));


app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));
//step1-apply sessions
app.use(session({
secret: "our secret is secrtet",
resave: false,
saveUninitialized: false
}));
//step2-intialize session
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});

//create userschema
// const userSchema = {
//     email: String,
//     password: String
// }
//change mongoose schema to mongoose encrptyion
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
})

//add passport local plugin to user schema- we can use hash and salt password and save into mongodb database
userSchema.plugin(passportLocalMongoose);
//add schema findorcreate
userSchema.plugin(findOrCreate)

//Secret String Instead of Two Keys in mongoose npm package documention

//FOR level3 copy and paste into .env
// const secret = "thisisourlittlesecret";
//use plugin and also read documentaion about plugin
//only we encrypt password field ...so we use only encrypt certain field
//save- encrypt
//find-decrypt
//for level2
// userSchema.plugin(encrypt, { secret: secret, encryptedFields: ['password'] });
//for level3
// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ['password'] });


//now we can use userschema to set model
const User = new mongoose.model("User", userSchema)

//sserialize passport
passport.use(User.createStrategy());

//comment out for use of oauth authentication - because when we click on google button it show failed to serialize user into session
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());
//now we use google serialize to allow session
passport.serializeUser(function(user, done){
    done(null, user.id);
})

passport.deserializeUser(function(id, done){
    User.findById(id, function(err, user){
        done(err, user)
    })
})

passport.use(new GoogleStrategy(
    {
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:4000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
   
  },
  function(accessToken, refreshToken, profile, cb) {
      console.log(profile);
      
      User.findOrCreate({ googleId: profile.id}, function (err,user){
          return cb(err,user);
      }
)
}))



//install findorcreate package
//mongodb cant save info without authorize in schema ....its latest update

app.get('/', function(req, res){
    res.render("home");
});

app.get("/auth/google",
    passport.authenticate("google", {scope: ["profile"]})
)
//after click on google id then redirect to locally to website
app.get("/auth/google/secrets",passport.authenticate('google', { failureRedirect: "/login"}),
   function(req,res){
       //succesfully authentication redirect home
       res.redirect('/secrets')
   }
)

app.get("/login", function(req,res){
    res.render("login")
})


//comment out because we are goona see each other secrets on page 
// app.get("/secrets", function(req,res){
//     //tocheck wether the user is authenticate or not
//     if(req.isAuthenticated()){
//      res.render("secrets")
//     }else{
//         res.redirect("/login")
//     }
// })


//anybody loged in or not logeed in can see secrets which is submitted by users after loggedin
//we dont see to check if authenticated,but instead we troll through our database and find all of the secrets that had been submitted on the database
//to do that we use model and find to look in collections and find all the places where field is secret  and there value
//how we do that -search mongodb field not null
//$ne:null mean it will pick secret field which is not equal to null from database
app.get("/secrets", function(req,res){
  User.find({"secret": {$ne: null}}, function(err,foundUsers){
      if(err){
          console.log(err);
          
      }else{
          if(foundUsers){
              //if founduser is not null then render there secret and we pass in a variable called  usersWithSecrets
              //because that essentially we are searching for ,we are trying tofind what the user have field of secret and
              //we pass in founuser as the value for this variable
            //   now we can pick this variable to secrets.ejs and paste into p tag  and in that wwe can run for each loop on this variable to loop through that in  array
            //then we add in a callback function in here to pick up all of the users inside the user with the user in secret array and for each of the user,we are going to render the value of user.secret field 
            //inside a p tag element ,we add user.secrets ,now this will loop through all the userwithsecrets for each user that has a secret we are render it inside a paragraph
            
              res.render("secrets", {usersWithSecrets: foundUsers})
          }
      }
  })
})


//let users submit there secrets and everyone can see there secrets ,so we check that user is authenticated or not if authenticated then user can submit there secrets 
app.get("/submit",function(req,res){
    if(req.isAuthenticated()){
        res.render("submit")
       }else{
           res.redirect("/login")
       }
})
app.post("/submit",function(req,res){
    //because in submit the input is text and there name is secret ,and when tap into this when this form get submitted through req.body.secret and that we will save into new contantant below
    const submittedSecret = req.body.secret;
    //next is to find the user in our database and then save this secret(submittedsecret) into there files
    //so how we know that who the current user are?actually passport can very handely save the details, because when we initiate new login session ,it will save the user details into req variable
    //so console.log(req.user), in which we can see what save in our current session
    console.log(req.user.id);
    //now we can see console that ,it post everything we have save about current user,we can acess there id and also there username
    //in database it is save there info ,now we can find user using there id in database,and save the secrets they created to this documents(in database user respective to there id)
    //so in order to do that first we have to amend our scema, so in addition to everthing inside this schema,we can add one more field-secrets 
    //and now when user make a post request then i am going to find a user that by req.user.id-because that refer to id that in our database
    //and then we have to add that secret ,that submitted to that secret field created in the schema
    //lets go head and tap into user model , we can find by id and once it get completed we write fun and give err or founduser(user exist or not)
   //then we are to save this founduser with newly updated secret and once that save is completed then we res.redirect them to secrets page so that they can see there own secrets alongside everybody else
//now we got user secret then we render this secret on secret page where other user can see there secrets with other secrets
 //to do that we have to update the app.get secret route =now we are not longer to authenticate the secret page ,because we all everyone to see each other secrets while they login


User.findById(req.user.id, function(err, foundUser){
        if(err){
            console.log(err);
            
        }else{
            if(foundUser){
                foundUser.secret = submittedSecret;
                foundUser.save(function(){
                    res.redirect("/secrets");
                })
               
            }
        }
    }) 
})

app.get("/register", function(req,res){
    res.render("register")
})
//users database 
//when user register on button
app.post("/register", function(req,res){
     User.register({username: req.body.username}, req.body.password,function(err, user){
         if(err){
             console.log(err);
             
             res.redirect("/register")
         }else{
             passport.authenticate("local")(req,res,function(){
                 //refer to saved cookies to check wether loged in or not
                      res.redirect("/secrets");
             })
         }
     })
})

app.get("/logout", function(req,res){
    req.logout();
    res.redirect("/")
})

//dictionary attack
//when user login
app.post("/login", function(req,res){

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    req.login(user, function(err){
        if(err){
            console.log(err);
            
        }else{
            passport.authenticate("local")(req,res, function(){
                res.redirect("secrets");
            })

        }
    })
})
//level one encryption - password is in plain text
//database encryption
//level 2-authentication or encryption
//level3-using environment variables to keep secrets safe=dotenv npm package
//level 4- because cipher method is weak in terms of encryption or decryption -so we use hashing-hashing also weak -dictionary attack
//install md5 npm
//level5-hashing and salting-use bcrypt algorithm //install bcrypt
//you can also see bcrypt version compitablity on nodejs website
//enigma machine -vedio
//ceaser cipher
//install mongoose encryption for database
//cookies and session-passportjs
//ouath 2.0 -third party login system
//make google credential then id and client id paste in env file


app.listen(4000, function(){
    console.log('server started on port 4000');
    
})