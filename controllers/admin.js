var _ = require('lodash');
var async = require('async');
var crypto = require('crypto');
var nodemailer = require('nodemailer');
var passport = require('passport');
var User = require('../models/User');
var users;
exports.index = function(req, res) {
  User.find({}, function(err, userData) {
    users = userData;
  });
};
