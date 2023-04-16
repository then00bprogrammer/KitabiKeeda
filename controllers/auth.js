const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const sendgridTransport = require('nodemailer-sendgrid-transport');
const { validationResult } = require('express-validator/check');

const User = require('../models/user');

// Create a transporter for nodemailer using sendgrid
const transporter = nodemailer.createTransport(
  sendgridTransport({
    auth: {
      api_key:
        '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'
    }
  })
);

// Controller for handling GET request for login page
exports.getLogin = (req, res, next) => {
  let message = req.flash('error');
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login',
    errorMessage: message,
    oldInput: {
      email: '',
      password: ''
    },
    validationErrors: []
  });
};

// Controller for handling GET request for signup page
exports.getSignup = (req, res, next) => {
  let message = req.flash('error');
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render('auth/signup', {
    path: '/signup',
    pageTitle: 'Signup',
    errorMessage: message,
    oldInput: {
      email: '',
      password: '',
      confirmPassword: ''
    },
    validationErrors: []
  });
};

// Controller for handling POST request for login
exports.postLogin = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).render('auth/login', {
      path: '/login',
      pageTitle: 'Login',
      errorMessage: errors.array()[0].msg,
      oldInput: {
        email: email,
        password: password
      },
      validationErrors: errors.array()
    });
  }

  // Find user in the database by email
  User.findOne({ email: email })
    .then(user => {
      if (!user) {
        // If no user found, render login page with error message
        return res.status(422).render('auth/login', {
          path: '/login',
          pageTitle: 'Login',
          errorMessage: 'Invalid email or password.',
          oldInput: {
            email: email,
            password: password
          },
          validationErrors: []
        });
      }
      // Compare input password with hashed password in the database
      bcrypt
        .compare(password, user.password)
        .then(doMatch => {
          if (doMatch) {
            // If password matches, create session and redirect to home page
            req.session.isLoggedIn = true;
            req.session.user = user;
            return req.session.save(err => {
              console.log(err);
              res.redirect('/');
            });
          }
          // If password does not match, render login page with error message
          return res.status(422).render('auth/login', {
            path: '/login',
            pageTitle: 'Login',
            errorMessage: 'Invalid email or password.',
            oldInput: {
              email: email,
              password: password
            },
            validationErrors: []
          });
        })
        .catch(err => {

          console.log(err);
          // Render login page with error message in case of any error
          return res.status(500).render('auth/login', {
            path: '/login',
            pageTitle: 'Login',
            errorMessage: 'An error occurred. Please try again later.',
            oldInput: {
              email: email,
              password: password
            },
            validationErrors: []
          });
        });
    })
    .catch(err => {
      // Render login page with error message in case of any error
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    });
};

// Controller for handling POST request for signup
exports.postSignup = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  const confirmPassword = req.body.confirmPassword;

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).render('auth/signup', {
      path: '/signup',
      pageTitle: 'Signup',
      errorMessage: errors.array()[0].msg,
      oldInput: {
        email: email,
        password: password,
        confirmPassword: confirmPassword
      },
      validationErrors: errors.array()
    });
  }

  // Hash the password using bcrypt
  bcrypt
    .hash(password, 12)
    .then(hashedPassword => {
      // Create a new user with hashed password
      const user = new User({
        email: email,
        password: hashedPassword,
        cart: { items: [] }
      });
      // Save the user in the database
      return user.save();
    })
    .then(result => {
      // Send an email to the user with a welcome message
      transporter.sendMail({
        to: email,
        from: 'shop@node-complete.com',
        subject: 'Signup Succeeded!',
        html: '<h1>You successfully signed up!</h1>'
      });
      // Redirect to login page with success message
      res.redirect('/login');
    })
    .catch(err => {
      // Render signup page with error message in case of any error
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    });
};

// Controller for handling POST request for logout
exports.postLogout = (req, res, next) => {
  // Destroy the session and redirect to home page
  req.session.destroy(err => {
    console.log(err);
    res.redirect('/');
  });
};

// Controller for handling GET request for reset password page
exports.getReset = (req, res, next) => {
  let message = req.flash('error');
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render('auth/reset', {
    path: '/reset',
    pageTitle: 'Reset Password',
    errorMessage: message
  });
};

// Controller for handling POST request for reset password
exports.postReset = (req, res, next) => {
  crypto.randomBytes(32, (err, buffer) => {
    if (err) {
      console.log(err);
      return res.redirect('/reset');
    }
    const token = buffer.toString('hex');
    User.findOne({ email: req.body.email })
      .then(user => {
        if (!user) {
          req.flash('error', 'No account with that email found.');
          return res.redirect('/reset');
        }
        user.resetToken = token;
        user.resetTokenExpiration = Date.now() + 3600000; // Token expiration time: 1 hour
        return user.save();
      })
      .then(result => {
        // Send an email to theuser with a reset password link
        transporter.sendMail({
          to: req.body.email,
          from: 'shop@node-complete.com',
          subject: 'Password Reset',
          html: '<p>You requested a password reset</p> <p>Click this <a href="http://localhost:3000/reset/${token}">link</a> to set a new password.</p> '});
        // Redirect to login page with success message
        req.flash('success', 'An email with instructions to reset your password has been sent.');
        res.redirect('/login');
      })
      .catch(err => {
        // Render reset password page with error message in case of any error
        const error = new Error(err);
        error.httpStatusCode = 500;
        return next(error);
      });
  });
};

// Controller for handling GET request for new password page
exports.getNewPassword = (req, res, next) => {
  const token = req.params.token;
  User.findOne({ resetToken: token, resetTokenExpiration: { $gt: Date.now() } })
    .then(user => {
      let message = req.flash('error');
      if (message.length > 0) {
        message = message[0];
      } else {
        message = null;
      }
      res.render('auth/new-password', {
        path: '/new-password',
        pageTitle: 'New Password',
        errorMessage: message,
        userId: user._id.toString(),
        passwordToken: token
      });
    })
    .catch(err => {
      // Render new password page with error message in case of any error
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    });
};

// Controller for handling POST request for new password
exports.postNewPassword = (req, res, next) => {
  const newPassword = req.body.password;
  const userId = req.body.userId;
  const passwordToken = req.body.passwordToken;
  let resetUser;

  User.findOne({
    resetToken: passwordToken,
    resetTokenExpiration: { $gt: Date.now() },
    _id: userId
  })
    .then(user => {
      resetUser = user;
      return bcrypt.hash(newPassword, 12);
    })
    .then(hashedPassword => {
      resetUser.password = hashedPassword;
      resetUser.resetToken = undefined;
      resetUser.resetTokenExpiration = undefined;
      return resetUser.save();
    })
    .then(result => {
      // Redirect to login page with success message
      req.flash('success', 'Password reset successful! You can now login with your new password.');
      res.redirect('/login');
    })
    .catch(err => {
      // Render new password page with error message in case of any error
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    });
};