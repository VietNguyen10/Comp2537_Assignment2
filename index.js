require("./utils.js");
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const MongoStore = require('connect-mongo');

const app = express();

const port = process.env.PORT || 4010;

const Joi = require("joi");

const expireTime = 60 * 60 * 1000; //expires after 1 hour

const saltRounds = 12;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('Users');

app.use(express.static('public'));

app.set('view engine', 'ejs');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({
  secret: node_session_secret,
  store: mongoStore, //default is memory store 
  saveUninitialized: false, 
  resave: true
 }
));

//Home page
app.get('/', (req, res) => {
  res.render("index.ejs");
});

//Login page
app.get('/login', (req, res) => {
  res.render("login.ejs");
});

app.post('/logginin', async(req, res) => {
  var username = req.body.username;
  var password = req.body.password;

  const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1, user_type: 1}).toArray();

	console.log(result);
	if (result.length != 1) {
		console.log("user not found");
		res.redirect("/login");
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.username = username;
		req.session.cookie.maxAge = expireTime;
    req.session.user_type = result[0].user_type;
		res.redirect('/members/');
		return;
	}
	else {
		console.log("incorrect password");
		res.redirect("/login");
		return;
	}
});

app.use('/members', sessionValidation);
//Show random animal images
app.get('/members', (req, res) => {
    var username = req.session.username;
    console.log(req.session.user_type);
    res.render("members.ejs", {username: username});
});

app.use('/admin', sessionValidation, adminValidation);
app.get('/admin', async (req, res) => {
    const result = await userCollection.find().project({username: 1, _id: 1, user_type: 1}).toArray();
    res.render('admin.ejs', {users: result});
});

// app.get('/logout', (req, res) => {
//   req.session.destroy();
//   res.redirect('/');
// });

app.get('/logout', function(req, res) {
  req.session.destroy(function(err){
     if(err){
        console.log(err);
     }else{
        console.log(session.email);
        res.redirect('/');
     }
  });
});

//Sign up page
app.get('/signup', (req, res) => {
    var missingEmail = req.query.missing;
    var existingEmail = req.query.existing;
    res.render('signup.ejs', { missingEmail: missingEmail, existingEmail: existingEmail });
  });
  

app.post('/submitUser', async (req,res) => {
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;
  var defaultType = "user";

const schema = Joi.object(
  {
    username: Joi.string().alphanum().max(20).required(),
    password: Joi.string().max(20).required(),
    email: Joi.string().email().required()
  });

const validationResult = schema.validate({username, password, email});
if (validationResult.error != null) {
   console.log(validationResult.error);
   res.redirect("/login");
   return;
 }

 const existingUser = await userCollection.findOne({ email: email });
 if (existingUser) {
   res.redirect('/signup?existing=true');
   return;
 }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  req.session.user_type = defaultType;

await userCollection.insertOne({username: username, password: hashedPassword, email: email, user_type: defaultType});
console.log("Inserted user");

res.render("submituser.ejs");
});

//Catch page that doesn't exist (must be placed after other pages)
app.use(express.static(__dirname + "/public"));
app.get("*", (req, res) => {
  res.status(404);
  res.render("404.ejs");
});

app.listen(port, () => {
    console.log(`Node application is listening on port ${port}`);
});

/*
  Check for a valid session,
  if user is not login redirect them to login page
*/
function isValidSession(req) {
  return req.session.authenticated;
}

function sessionValidation(req, res, next) {
  if(isValidSession(req)){
    next();
  } else{
    res.redirect('/login');
  }
}

/*
  Check if the user is an admin,
  if user is not admin throw an error and redirect them 
  back to members page
*/
// promote("Hai");
function isAdmin(req) {
  if(req.session.user_type === "admin") {
    return true;
  }else{
    return false;
  }
}

function adminValidation (req, res, next) {
  if(!isAdmin(req)) {
    res.status(403);
    res.render("accessDenied", {error: "admin access only"});
    return;
  } else{
    next();
  }
}

// async function promote(username) {
//   try {
//     await userCollection.updateOne({ username: username }, { $set: { user_type: "admin" } });
//     console.log(`User type updated for user ${username}`);
//   } catch (err) {
//     console.error(`Error updating user type for user ${username}: ${err.message}`);
//   }
// }

// async function demote(username) {
//   try {
//     await userCollection.updateOne({ username: username }, { $set: { user_type: "user" } });
//     console.log(`User type updated for user ${username}`);
//   } catch (err) {
//     console.error(`Error updating user type for user ${username}: ${err.message}`);
//   }
// }

app.post('/demote/:username', async (req, res) => {
  const username = req.params.username;
  try {
    await userCollection.updateOne({ username: username }, { $set: { user_type: "user" } });
    console.log(`User type updated for user ${username}`);
  } catch (err) {
    console.error(`Error updating user type for user ${username}: ${err.message}`);
    res.status(500).send(`Error updating user type for user ${username}: ${err.message}`);
  }
});

app.post('/promote/:username', async (req, res) => {
  const username = req.params.username;
  try {
    await userCollection.updateOne({ username: username }, { $set: { user_type: "admin" } });
    console.log(`User type updated for user ${username}`);
  } catch (err) {
    console.error(`Error updating user type for user ${username}: ${err.message}`);
    res.status(500).send(`Error promoting user ${username}: ${err.message}`);
  }
});





