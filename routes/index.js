var express = require('express');
var router = express.Router();

var User = require('../models/user');

router.get('/profile', ensureAuthenticated, function(req, res){
	res.render('profile.handlebars', {
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

module.exports = router;