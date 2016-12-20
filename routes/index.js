var express = require('express');
var router = express.Router();
var mongoose = require('mongoose');
var mongo = require('mongodb');
var User = require('../models/users.js');

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Guestbook++' });
  console.log('This is the index.js file')
});

router.get('/auth/facebook', function(req, res, next){
    req.passport.authenticate('facebook')(req, res, next);
});

router.get('/auth/facebook/callback', function(req, res, next){
    req.passport.authenticate('facebook', {
        successRedirect: '/',
        failureRedirect: '/login' }
    )(req, res, next); // missing function call
});

module.exports = router;
