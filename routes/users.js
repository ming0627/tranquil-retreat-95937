/*##########################################################################################################
Version 5.0.1
File Description:	
No	Date				By						Change Log 
1.	20180407		Chee Ming			Route between index.js to backend posting
2. 	20180407		Chee Ming 		Remove unnecessary unlink function
##############################################################################################################*/

var express = require('express');
var router = express.Router();
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;

var User = require('../models/user');

// load the auth variables
var configAuth = require('../config/auth'); // use this one for testing

// =============================================================================
// normal routes ==================================================
// =============================================================================

	// HOME =========================
	router.get('/', function(req, res){
		res.render('index.ejs');
	});

	// PROFILE SECTION =========================
	router.get('/profile', ensureAuthenticated, function(req, res){
		res.render('profile.ejs', {
			user : req.user
		}); // if it's logon then go to this
	});

	// LOGOUT ==============================
	router.get('/logout', function(req, res){
		req.logout();
	
		req.flash('success_msg', 'You are logged out');
	
		res.redirect('/');
	});

// =============================================================================
// AUTHENTICATE (FIRST LOGIN) ==================================================
// =============================================================================

	// locally --------------------------------
		// LOGIN ===============================
		// show the login form
		router.get('/login', function(req, res){
			if(req.user) {
				res.render('profile.ejs');
			}else{
				res.render('login.ejs', { message: req.flash('loginMessage') });
			}
		});

		// process the login form	
		router.post('/login',passport.authenticate('local-login', {
			successRedirect:'/profile', 
			failureRedirect:'/login',
			failureFlash: true
		}));

		// SIGNUP =================================
		// show the signup form
		router.get('/register', function(req, res){
			res.render('register.ejs', { message: req.flash('loginMessage') });
		});

		// process the signup form
		router.post('/register', passport.authenticate('local-signup', {
			successRedirect : '/profile', // redirect to the secure profile section
			failureRedirect : '/register', // redirect back to the signup page if there is an error
			failureFlash : true // allow flash messages
		}));


	// facebook -------------------------------
		// send to facebook to do the authentication
		router.get('/auth/facebook', passport.authenticate('facebook', { scope : 'email' }));

		// handle the callback after facebook has authenticated the user
		router.get('/auth/facebook/callback',
			passport.authenticate('facebook', {
				successRedirect : '/profile',
				failureRedirect : '/'
			}));

// =============================================================================
// AUTHORIZE (ALREADY LOGGED IN / CONNECTING OTHER SOCIAL ACCOUNT) =============
// =============================================================================

	// locally --------------------------------
		router.get('/connect/local', function(req, res) {
			res.render('connect-local.ejs', { message: req.flash('loginMessage') });
		});
		router.post('/connect/local', passport.authenticate('local-signup', {
			successRedirect : '/profile', // redirect to the secure profile section
			failureRedirect : '/connect/local', // redirect back to the signup page if there is an error
			failureFlash : true // allow flash messages
		}));

	// facebook -------------------------------
		// send to facebook to do the authentication
		router.get('/connect/facebook', passport.authorize('facebook', { scope : 'email' }));

		// handle the callback after facebook has authorized the user
		router.get('/connect/facebook/callback',
			passport.authorize('facebook', {
				successRedirect : '/profile',
				failureRedirect : '/'
			}));



/* =============================================================================
// UNLINK ACCOUNTS =============================================================
// =============================================================================
// used to unlink accounts. for social accounts, just remove the token
// for local account, remove email and password
// user account will stay active in case they want to reconnect in the future

	// local -----------------------------------
		router.get('/unlink/local', function(req, res) {
			var user            = req.user;
			user.local.username = undefined;
			user.local.password = undefined;
			User.createUser(user, function(err, user){
				if(err) throw err;
				res.redirect('/profile');
			});
		});

	// facebook -------------------------------
		router.get('/unlink/facebook', function(req, res) {
			var user            = req.user;
			user.facebook.token = undefined;
			user.save(function(err) {
				res.redirect('/profile');
			});
		});
*/


passport.use('local-login', new LocalStrategy({ 
		passReqToCallback: true 
	},
  function(req, username, password, done) {
		process.nextTick(function() {
			User.getUserByUsername(username, function(err, user){
			if(err) 
				return done(err);
			if(!user){
				//return done(null, false, {loginMessage: 'No user found.'});
				return done(null, false, req.flash('loginMessage', 'No user found.'));
			}

			User.comparePassword(password, user.local.password, function(err, isMatch){
				if(err) 
					return done(err);
				if(isMatch){
					return done(null, user);
				} else {
					return done(null, false, req.flash('loginMessage', 'Oops! Wrong password.'));
					//return done(null, false, {loginMessage: 'No user found.'});
				}
			});
			});
		});
	}));

		// process the signup form --- 2
		/*router.post('/register', function(req, res){
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
				res.render('register.ejs',{
					errors:errors
				});
			} else {
				var newUser = new User({
					'local.username': username,
					'local.email':email,
					'local.name': name,
					'local.password': password
				});

				User.createUser(newUser, function(err, user){
					if(err) throw err;
					console.log(User);
				});

				req.flash('success_msg', 'You are registered and can now login');

				res.redirect('/login');
			}
		});*/
	
	passport.use('local-signup', new LocalStrategy({
			passReqToCallback : true // allows us to pass in the req from our route (lets us check if a user is logged in or not)
	},
	function(req, username, password, done) {

			// asynchronous
			process.nextTick(function() {

					//  Whether we're signing up or connecting an account, we'll need
					//  to know if the email address is in use.
					User.getUserByUsername(username, function(err, existingUser){

						var name = req.body.name;
						var email = req.body.email;

							// if there are any errors, return the error
							if (err)
									return done(err);

							// check to see if there's already a user with that email
							if (existingUser) 
									return done(null, false, req.flash('signupMessage', 'That email is already taken.'));

							//  If we're logged in, we're connecting a new local account.
							if(req.user) {
									var user            = req.user;
									user.local.username = username;
									user.local.password = password;

									User.createUser(user, function(err, user){
										if(err) throw err;
										return done(null, user);
									});
							} 

							//  We're not logged in, so we're creating a brand new user.
							else {
									// create the user
									var newUser            = new User();

									newUser.local.username    = username;
									newUser.local.password 		= password; // use the generateHash function in our user model
									newUser.local.name 				= name; // use the generateHash function in our user model
									newUser.local.email 			= email; // use the generateHash function in our user model

									User.createUser(newUser, function(err, user){
										if(err) throw err;
										return done(null, newUser);
									});
							}

					});
			});

	}));

	// =========================================================================
	// FACEBOOK ================================================================
	// =========================================================================
	passport.use(new FacebookStrategy({

		clientID        : configAuth.facebookAuth.clientID,
		clientSecret    : configAuth.facebookAuth.clientSecret,
		callbackURL     : configAuth.facebookAuth.callbackURL,
		profileFields   : configAuth.facebookAuth.profileFields,
		passReqToCallback : true // allows us to pass in the req from our route (lets us check if a user is logged in or not)

},
function(req, token, refreshToken, profile, done) {

		// asynchronous
		process.nextTick(function() {

				// check if the user is already logged in
				if (!req.user) {

						User.findOne({ 'facebook.id' : profile.id }, function(err, user) {
								if (err)
										return done(err);

								if (user) {

										// if there is a user id already but no token (user was linked at one point and then removed)
										if (!user.facebook.token) {
												user.facebook.token = token;
												user.facebook.name  = profile.name.givenName + ' ' + profile.name.familyName;
												user.facebook.email = profile.emails[0].value;

												user.save(function(err) {
														if (err)
																throw err;
														return done(null, user);
												});
										}

										return done(null, user); // user found, return that user
								} else {
										// if there is no user, create them
										var newUser            = new User();

										newUser.facebook.id    = profile.id;
										newUser.facebook.token = token;
										newUser.facebook.name  = profile.name.givenName + ' ' + profile.name.familyName;
										newUser.facebook.email = profile.emails[0].value;

										newUser.save(function(err) {
												if (err)
														throw err;
												return done(null, newUser);
										});
								}
						});

				} else {
						// user already exists and is logged in, we have to link accounts
						var user            = req.user; // pull the user out of the session

						user.facebook.id    = profile.id;
						user.facebook.token = token;
						user.facebook.name  = profile.name.givenName + ' ' + profile.name.familyName;
						user.facebook.email = profile.emails[0].value;

						user.save(function(err) {
								if (err)
										throw err;
								return done(null, user);
						});

				}
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

function ensureAuthenticated(req, res, next){
	if(req.isAuthenticated()){
		return next();
	} else {
		//req.flash('error_msg','You are not logged in');
		//res.redirect('/users/login'); //SHERMAN : 1ST DEFAULT PAGE
		res.redirect('/'); //SHERMAN : 1ST DEFAULT PAGE
	}
}
module.exports = router;