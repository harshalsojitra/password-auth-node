const express = require('express');

const router = express.Router();

const bcrypt = require('bcryptjs');

const passport = require('passport');

//load user model
const User = require('../models/User');

//Login page.
router.get('/login', (req,res)=> res.render('login'));

//Register page.
router.get('/register', (req, res) => res.render('register'));

//Register handle.
router.post('/register', (req,res) => {
	const { name, email, password, password2 } = req.body;
	let errors = [];

	//check all required filleds
	if(!name || !email || !password || !password2)
	{
		errors.push({ msg: 'Please fill in all field'});
	}

	//check passwords match 
	if(password !== password2)
	{	
		errors.push({msg: 'Password do not match'});
	}

	//check pass. length
	if(password.length < 6){
		errors.push({msg:'password should be at least 6 characters'});
	}

	if(errors.length > 0)
	{
		res.render('register', {
			errors,
			name, 
			email,
			password,
			password2
		});
	}else {
		User.findOne({email: email})
			.then(user => {
				if(user) {
					//user exists.
					errors.push({ msg: 'Email is already exists' });
					res.render('register', {
						errors,
						name,
						email,
						password,
						password2
					});
				}else {
					const newUser = new User({
						name,
						email,
						password
					});

					//Hash password
					bcrypt.genSalt(10, (err, salt) => 
						bcrypt.hash(newUser.password, salt,(err, hash) => {
							if(err) throw err;
							//set password to hash
							newUser.password = hash;
							//save user
							newUser.save()
								.then(user => {
									req.flash('success_msg', 'You are now register and can login');
									res.redirect('/users/login');
								})
									.catch(err => console.log(err));

					}))
				}
			});
	}
});  

//Login handle
router.post('/login', (req, res, next) => {
	passport.authenticate('local', {
		successRedirect: '/dashboard',
		failureRedirect: '/users/login',
		failureFlash: true
	})(req, res, next);
});

//logout handle
router.get('/logout', (req, res) => {
	req.logout();
	req.flash('success_msg', 'You are logged out');
	res.redirect('/users/login');
})
module.exports = router;	