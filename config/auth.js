// config/auth.js

// expose our config directly to our application using module.exports
module.exports = {

	'facebookAuth' : {
        'clientID' 		: '174259806630938', // Fate Test1 App ID
        'clientSecret' 	: '4e83f29eecdc0fab345ed5d79da4d5bd', // Fate App Secret
		'callbackURL' 	: 'http://localhost:3000/auth/facebook/callback',
		'profileFields'	: ['id', 'name', 'displayName', 'picture.type(large)', 'hometown', 'profileUrl', 'email']
    },

	'twitterAuth' : {
		'consumerKey' 		: 'your-consumer-key-here',
		'consumerSecret' 	: 'your-client-secret-here',
		'callbackURL' 		: 'http://localhost:8080/auth/twitter/callback'
	},

	'googleAuth' : {
		'clientID' 		: 'your-secret-clientID-here',
		'clientSecret' 	: 'your-client-secret-here',
		'callbackURL' 	: 'http://localhost:8080/auth/google/callback'
	}

};