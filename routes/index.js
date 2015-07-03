var express = require('express');
var router = express.Router();
var passport=require('passport');


	/* GET home page. */
	router.get('/', function(req, res, next) {
	  res.render('index', { title: 'WH*!',user:req.user });
	});


	router.get('/dashboard', function(req, res, next) {
	  res.render('dashboard', { title: 'WH*!',user:req.user });
	});


	router.get('/login', function(req, res) {

        // render the page and pass in any flash data if it exists
        res.render('login.ejs', { message: req.flash('loginMessage') }); 
    });
	router.post('/login',passport.authenticate('local-login',{
    	successRedirect:'/',
    	failureRedirect:'/login',
    	failureFlash:true
    }));

    
    router.get('/signup', function(req, res) {
        // render the page and pass in any flash data if it exists
        res.render('signup.ejs', { message: req.flash('signupMessage') });
    });
    router.post('/signup',passport.authenticate('local-signup',{
    	successRedirect:'/profile',
    	failureRedirect:'/signup',
    	failureFlash:true
    }));


    router.get('/profile', isLoggedIn, function(req, res) {
        res.render('profile.ejs', {
            user : req.user // get the user out of session and pass to template
        });
    });

    router.get('/logout', function(req, res) {
        req.logout();
        res.redirect('/');
    	});
    ////////////////////////////////////////////////
    //Facebook routes
    ////////////////////////////////////////////////
	router.get('/auth/facebook',passport.authenticate('facebook',{scope:'email'}));

    router.get('/auth/facebook/callback',passport.authenticate('facebook',{
        successRedirect:'/profile',
        failureRedirect:'/'
    }));

    //functions
    function isLoggedIn(req, res, next) {
	    // if user is authenticated in the session, carry on 
	    if (req.isAuthenticated())
	        return next();

	    // if they aren't redirect them to the home page
	    res.redirect('/');
	}

module.exports = router;
