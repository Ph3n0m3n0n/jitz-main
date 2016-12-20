var express = require('express');
var router = express.Router();
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;

var User = require('../models/users');
var configAuth = require('../config/auth');

// Register
router.get('/register', function(req, res){
	res.render('register');
});

// Login
router.get('/login', function(req, res){
	res.render('login');
});

// Register User
router.post('/register', function(req, res){
	var name = req.body.name;
	var email = req.body.email;
	var username = req.body.username;
	var password = req.body.password;
	var password2 = req.body.password2;

	// Validation
	req.checkBody('name', 'Name is required').notEmpty();
	req.checkBody('email', 'Email is required').notEmpty();
	req.checkBody('email', 'Email is not valid').isEmail();
	req.checkBody('username', 'Username is required').notEmpty();
	req.checkBody('password', 'Password is required').notEmpty();
	req.checkBody('password2', 'Passwords do not match').equals(req.body.password);

	var errors = req.validationErrors();

	if(errors){
		res.render('register',{
			errors:errors
		});
	} else {
		var newUser = new User({
			name: name,
			email:email,
			username: username,
			password: password
		});

		User.createUser(newUser, function(err, user){
			if(err) throw err;
      router.post('/adduser', function(req, res) {
          var db = req.db;
          var collection = db.get('userlist');
          collection.insert(req.body, function(err, result){
              res.send(
                  (err === null) ? { msg: '' } : { msg: err }
              );
          });
      });
		});

    /* GET userlist */
    router.get('/userlist', function(req, res) {
        var db = req.db;
        var collection = db.get('userlist');
        collection.find({},{},function(e,docs) {
            res.json(docs);
        });
    });

    /* DELETE to delete user. */
    router.delete('/deleteuser/:id', function(req, res) {
        var db = req.db;
        var collection = db.get('userlist');
        var userToDelete = req.params.id;
        collection.remove({ '_id' : userToDelete }, function(err) {
            res.send((err === null) ? { msg: '' } : { msg:'error: ' + err });
        });
    });
    

		req.flash('success_msg', 'You are registered and can now login');

		res.redirect('/users/login');
	}
});

passport.use(new LocalStrategy(
  function(username, password, done) {
   User.getUserByUsername(username, function(err, user){
   	if(err) throw err;
   	if(!user){
   		return done(null, false, {message: 'Unknown User'});
   	}

   	User.comparePassword(password, user.password, function(err, isMatch){
   		if(err) throw err;
   		if(isMatch){
   			return done(null, user);
   		} else {
   			return done(null, false, {message: 'Invalid password'});
   		}
   	});
   });
  }));

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.getUserById(id, function(err, user) {
    done(err, user);
  });
});

router.post('/login',
  passport.authenticate('local', {successRedirect:'/', failureRedirect:'/users/login',failureFlash: true}),
  function(req, res) {
    res.redirect('/');
  });

router.get('/logout', function(req, res){
	req.logout();

	req.flash('success_msg', 'Goodbye!');

	res.redirect('/users/login');
});

// Redirect the user to Facebook for authentication.  When complete,
// Facebook will redirect the user back to the application at
//     /auth/facebook/callback
// (Changed from app.get to router.get because I think that is the correct path.
// Tried using app.get and it broke the server. router.get is the correct path.
// This code was copied directly from Passport documentation @
// http://passportjs.org/docs/facebook )
router.get('/auth/facebook', passport.authenticate('facebook'));

// Facebook will redirect the user to this URL after approval.  Finish the
// authentication process by attempting to obtain an access token.  If
// access was granted, the user will be logged in.  Otherwise,
// authentication has failed.
router.get('/auth/facebook/callback',
  passport.authenticate('facebook', { successRedirect: '/profile',
                                      failureRedirect: '/login' }));


// This is my Facebook Strategy retrieved from Passport docs @ http://passportjs.org/docs/facebook
// Problem with this code? Server shutdown. Fixed when section below is
// commented out.
passport.use(new FacebookStrategy({
	clientID: configAuth.facebookAuth.clientID,
	clientSecret: configAuth.facebookAuth.clientSecret,
	callbackURL: configAuth.facebookAuth.callbackURL
},
function(accessToken, refreshToken, profile, done) {
	process.nextTick(function(){
	User.findOne({'facebook.id': profile.id}, function(err, user){
	if(err)
		return done(err);
	if(user)
		return done(null, user);
	else {
		var newUser = new User();
			newUser.facebook.id = profile.id;
			newUser.facebook.token = accessToken;
			newUser.facebook.name = profile.name.givenName + ' ' + profile.name.familyName;
			//newUser.facebook.email = profile.emails[0].value;

			newUser.save(function(err){
				if(err) throw err;
					return done(null, newUser);
			})
					console.log(profile);
				}
 });
 });
 }

 ));

module.exports = router;
