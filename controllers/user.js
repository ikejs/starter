var _ = require('lodash');
var async = require('async');
var crypto = require('crypto');
var nodemailer = require('nodemailer');
var passport = require('passport');
var User = require('../models/User');
var multer = require('multer');
var path = require('path');
var upload = multer({ dest: path.join(__dirname, 'uploads') });
var multer = require('multer');
var fs = require('fs');
var dateFormat = require('dateformat');

/**
 * GET /login
 * Login page.
 */
exports.getLogin = function(req, res) {
  if (req.user) {
    return res.redirect('/');
  }
  res.render('login', {
    title: 'Login'
  });
};


/**
 * GET /account/dashboard
 * User dashboard page.
 */
exports.getDashboard = function(req, res) {
  res.render('account/dashboard', {
    user: req.user
  });
};

/**
 * POST /login
 * Sign in using email and password.
 */
exports.postLogin = function(req, res, next) {
  req.assert('email', 'Email is not valid').isEmail();
  req.assert('password', 'Password cannot be blank').notEmpty();
  req.sanitize('email').normalizeEmail();

  var errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('/login');
  }

  passport.authenticate('local', function(err, user, info) {
    if (err) {
      return next(err);
    }
    if (!user) {
      req.flash('errors', info);
      return res.redirect('/login');
    }
    req.logIn(user, function(err) {
      if (err) {
        return next(err);
      }
      return res.redirect('/account/dashboard');
    });
  })(req, res, next);
};

/**
 * GET /logout
 * Log out.
 */
exports.logout = function(req, res) {
  req.logout();
  res.redirect('/');
};

/**
 * GET /signup
 * Signup page.
 */
exports.getSignup = function(req, res) {
  if (req.user) {
    return res.redirect('/');
  }
  res.render('signup', {
    title: 'Create Account'
  });
};


/**
 * POST /signup
 * Create a new local account.
 */
exports.postSignup = function(req, res, next) {
  req.assert('email', 'Email is not valid').isEmail();
  req.assert('password', 'Password must be at least 4 characters long').len(4);
  req.assert('confirmPassword', 'Passwords do not match').equals(req.body.password);
  req.sanitize('email').normalizeEmail();

  var errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('/signup');
  }

  var user = new User({
    email: req.body.email,
    password: req.body.password,
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      username: req.body.username
  });

  User.findOne({ email: req.body.email }, function(err, existingUser) {
    if (existingUser) {
      req.flash('errors', { msg: 'Account with that email address already exists.' });
      return res.redirect('/signup');
    }
    User.findOne({ lower: req.body.username.toLowerCase() }, function(err, existingUser) {
      if (existingUser) {
        req.flash('errors', { msg: 'Account with that username address already exists.' });
        return res.redirect('/signup');
      }
    user.save(function(err) {
      if (err) {
        return next(err);
      }
      req.logIn(user, function(err) {
        if (err) {
          return next(err);
        }
        res.redirect('/');
      });
    });
  });
});
};


exports.account = function(req, res) {
  res.render('account/');
};

/**
 * GET /account
 * Profile page.
 */
exports.getAccount = function(req, res) {
  res.render('account/profile', {
    created: dateFormat(req.user.createdAt, "mmmm dS, yyyy")
  });
};

/**
 * POST /account/profile
 * Update profile information.
 */
 exports.postUpdateProfile = function(req, res, next) {
   req.assert('email', 'Please enter a valid email address.').isEmail();
   req.sanitize('email').normalizeEmail();

   var errors = req.validationErrors();

   if (errors) {
     req.flash('errors', errors);
     return res.redirect('/account/profile');
   }

   User.findById(req.user._id, function(err, user) {
     if (err) {
       return next(err);
     }
     if (req.body.email != user.email) {
       user.email = req.body.email || '';
       user.save(function(err) {
         if (err) {
           if (err.code === 11000) {
             req.flash('errors', { msg: 'Account with that email address already exists.' });
             return res.redirect('/account/profile');
           } else {
             return res.send({ msg: err, errors: true });
           }
         }
         req.flash('success', { msg: 'Account email updated.' });
         res.redirect('/account/profile');
       });
     } else if (req.body.username != user.username) {
       User.findOne({ username: req.body.username }, function(err, existingUser) {
         if (existingUser) {
           req.flash('errors', { msg: 'Account with that username address already exists.' });
           return res.redirect('/account/profile');
         } else {
           user.username = req.body.username || '';
           user.save(function(err) {
             if (err) {
               if (err.code === 11000) {
                 req.flash('errors', { msg: 'The email address you have entered is already associated with an account.' });
                 return res.redirect('/account/profile');
               } else {
                 req.flash('errors', { msg: err });
                 return res.redirect('/account/profile');
               }
             }
             req.flash('success', { msg: 'Account username updated.' });
             res.redirect('/account/profile');
           });
         }
     });
   } else if (req.body.firstName != user.firstName) {
     user.firstName = req.body.firstName || '';
     user.save(function(err) {
       if (err) {
           req.flash('errors', { msg: err });
           return res.redirect('/account/profile');
         } else {
           req.flash('success', { msg: 'Account first name updated.' });
           res.redirect('/account/profile');
         }
     });
   } else if (req.body.lastName != user.lastName) {
     user.lastName = req.body.lastName || '';
     user.save(function(err) {
       if (err) {
           req.flash('errors', { msg: err });
           return res.redirect('/account/profile');
         } else {
           req.flash('success', { msg: 'Account last name updated.' });
           res.redirect('/account/profile');
         }
     });
   } else {
     req.flash('success', { msg: 'Profile information updated.' });
     res.redirect('/account/profile');
   }
   });
 };

/**
 * POST /account/password
 * Update current password.
 */
exports.postUpdatePassword = function(req, res, next) {
  req.assert('password', 'Password must be at least 4 characters long').len(4);
  req.assert('confirmPassword', 'Passwords do not match').equals(req.body.password);

  var errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('/account/profile');
  }

  User.findById(req.user.id, function(err, user) {
    if (err) {
      return next(err);
    }
    user.password = req.body.password;
    user.save(function(err) {
      if (err) {
        return next(err);
      }
      req.flash('success', { msg: 'Password has been changed.' });
      res.redirect('/');
    });
  });
};

exports.postDeleteAccount = function(req, res, next) {

   User.remove({ _id: req.user._id }, function(err) {
     if (err) {
       return next(err);
     }
     req.flash('info', { msg: 'Your account has been deleted.' });
     req.logout();
     res.redirect('/');
   });
};

/**
 * GET /account/unlink/:provider
 * Unlink OAuth provider.
 */
exports.getOauthUnlink = function(req, res, next) {
  var provider = req.params.provider;
  User.findById(req.user.id, function(err, user) {
    if (err) {
      return next(err);
    }
    user[provider] = undefined;
    user.tokens = _.reject(user.tokens, function(token) { return token.kind === provider; });
    user.save(function(err) {
      if (err) {
        return next(err);
      }
      req.flash('info', { msg: provider + ' account has been unlinked.' });
      res.redirect('/');
    });
  });
};

/**
 * GET /reset/:token
 * Reset Password page.
 */
exports.getReset = function(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect('/');
  }
  User
    .findOne({ passwordResetToken: req.params.token })
    .where('passwordResetExpires').gt(Date.now())
    .exec(function(err, user) {
      if (err) {
        return next(err);
      }
      if (!user) {
        req.flash('errors', { msg: 'Password reset token is invalid or has expired.' });
        return res.redirect('/forgot');
      }
      res.render('reset', {
        title: 'Password Reset'
      });
    });
};

/**
 * POST /reset/:token
 * Process the reset password request.
 */
exports.postReset = function(req, res, next) {
  req.assert('password', 'Password must be at least 4 characters long.').len(4);
  req.assert('confirm', 'Passwords must match.').equals(req.body.password);

  var errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('back');
  }

  async.waterfall([
    function(done) {
      User
        .findOne({ passwordResetToken: req.params.token })
        .where('passwordResetExpires').gt(Date.now())
        .exec(function(err, user) {
          if (err) {
            return next(err);
          }
          if (!user) {
            req.flash('errors', { msg: 'Password reset token is invalid or has expired.' });
            return res.redirect('back');
          }
          user.password = req.body.password;
          user.passwordResetToken = undefined;
          user.passwordResetExpires = undefined;
          user.save(function(err) {
            if (err) {
              return next(err);
            }
            req.logIn(user, function(err) {
              done(err, user);
            });
          });
        });
    },
    function(user, done) {
      var transporter = nodemailer.createTransport({
        service: 'SendGrid',
        auth: {
          user: process.env.SENDGRID_USER,
          pass: process.env.SENDGRID_PASSWORD
        }
      });
      var mailOptions = {
        to: user.email,
        from: 'hackathon@starter.com',
        subject: 'Your Hackathon Starter password has been changed',
        text: 'Hello,\n\n' +
          'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'
      };
      transporter.sendMail(mailOptions, function(err) {
        req.flash('success', { msg: 'Success! Your password has been changed.' });
        done(err);
      });
    }
  ], function(err) {
    if (err) {
      return next(err);
    }
    res.redirect('/');
  });
};

/**
 * GET /forgot
 * Forgot Password page.
 */
exports.getForgot = function(req, res) {
  if (req.isAuthenticated()) {
    return res.redirect('/');
  }
  res.render('forgot', {
    title: 'Forgot Password'
  });
};

/**
 * POST /forgot
 * Create a random token, then the send user an email with a reset link.
 */
exports.postForgot = function(req, res, next) {
  req.assert('email', 'Please enter a valid email address.').isEmail();

  var errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('/forgot');
  }

  async.waterfall([
    function(done) {
      crypto.randomBytes(16, function(err, buf) {
        var token = buf.toString('hex');
        done(err, token);
      });
    },
    function(token, done) {
      User.findOne({ email: req.body.email.toLowerCase() }, function(err, user) {
        if (!user) {
          req.flash('errors', { msg: 'No account with that email address exists.' });
          return res.redirect('/forgot');
        }
        user.passwordResetToken = token;
        user.passwordResetExpires = Date.now() + 3600000; // 1 hour
        user.save(function(err) {
          done(err, token, user);
        });
      });
    },
    function(token, user, done) {
      var transporter = nodemailer.createTransport({
        service: 'SendGrid',
        auth: {
          user: process.env.SENDGRID_USER,
          pass: process.env.SENDGRID_PASSWORD
        }
      });
      var mailOptions = {
        to: user.email,
        from: 'hackathon@starter.com',
        subject: 'Reset your password on Hackathon Starter',
        text: 'You are receiving this email because you (or someone else) have requested the reset of the password for your account.\n\n' +
          'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
          'http://' + req.headers.host + '/reset/' + token + '\n\n' +
          'If you did not request this, please ignore this email and your password will remain unchanged.\n'
      };
      transporter.sendMail(mailOptions, function(err) {
        req.flash('info', { msg: 'An e-mail has been sent to ' + user.email + ' with further instructions.' });
        done(err);
      });
    }
  ], function(err) {
    if (err) {
      return next(err);
    }
    res.redirect('/forgot');
  });
};
