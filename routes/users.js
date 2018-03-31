var express = require('express');
var router = express.Router();
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;

var User = require('../models/user');

// Register
router.get('/register', function(req, res){
	res.render('register.handlebars');
});

// Login
router.get('/login', function(req, res){
	if(req.user) {
		res.render('index.handlebars');
	}else{
		res.render('login.ejs', { message: req.flash('loginMessage') });
	}
});

// Login
router.get('/', function(req, res){
	res.render('index.ejs');
});

// Profile
router.get('/profile', ensureAuthenticated, function(req, res){
	res.render('index.handlebars', {
		user : req.user
	}); // if it's logon then go to this
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
		res.render('register.handlebars',{
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

		res.redirect('/users/login');
	}
});

passport.use('local-login', new LocalStrategy({ 
		passReqToCallback: true 
	},
  function(req, username, password, done) {
		process.nextTick(function() {
			User.getUserByUsername(username, function(err, user){
			if(err) throw err;
			if(!user){
				//return done(null, false, {loginMessage: 'No user found.'});
				return done(null, false, req.flash('loginMessage', 'No user found.'));
			}

			User.comparePassword(password, user.local.password, function(err, isMatch){
				if(err) throw err;
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

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.getUserById(id, function(err, user) {
    done(err, user);
  });
});

router.post('/login',passport.authenticate('local-login', {
	successRedirect:'/profile', 
	failureRedirect:'/login',
	failureFlash: true
}));

router.get('/logout', function(req, res){
	req.logout();

	req.flash('success_msg', 'You are logged out');

	res.redirect('/');
});

module.exports = router;