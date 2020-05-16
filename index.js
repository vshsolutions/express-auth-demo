var express = require('express');
var app = express();
const JWT = require('jsonwebtoken')

var bodyParser = require('body-parser')
app.use(bodyParser.json())

const mongoose = require('mongoose');
mongoose.connect('mongodb://localhost:27017/test', {useNewUrlParser: true, useUnifiedTopology: true});

const User = mongoose.model('User',{
    password: String,
    email: String
});

const passport = require('passport')
const JwtStrategy = require('passport-jwt').Strategy
const { ExtractJwt } = require('passport-jwt')

passport.use(
  new JwtStrategy(
    {
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: "some secret",
      passReqToCallback: true
    },
    async (req, payload, done) => {
      try {
        // Find the user specified in token
        const user = await User.findOne({ _id: payload.sub })
        // If user doesn't exists, handle it
        if (!user) {
          return done(null, false)
        }

        // Otherwise, return the user
        req.user = user
        done(null, user)
      } catch (error) {
        done(error, false)
      }
    }
  )
)


const passportJWT = passport.authenticate('jwt', { session: false })

const signToken = (user) => {
  return JWT.sign(
    {
      iss: 'demo',
      sub: user._id,
      iat: new Date().getTime(), // current time
      exp: new Date().setDate(new Date().getDate() + 1) // current time + 1 day ahead
    },
    "some secret"
  )
}


app.post('/signup', async function(req, res){
	//create user and store it in db

	//check if user exists?

	const existingUser = User.findOne({email:req.body.email});
	if(existingUser){
		console.log('User exists!');
		res.send({message:"user exists!"});
	}else{
		const user = new User({ ...req.body  });
		const savedUser=await user.save()

		console.log('User created successfully');
		res.send(signToken(savedUser))
	}


	

});

app.post('/login', async function(req, res){
	//see if user exist in database
	const existingUser = await User.findOne({...req.body});
	console.log("data",existingUser)
	if(existingUser){
		console.log('User authenticated!');
		res.send(signToken(existingUser));
	}else{
		console.log('Invalid credentials!');
		res.send({message:"Invalid credentials!"})
	}
});


app.get('/private',passportJWT, function(req, res){
		res.send(req.user)
});


app.get('/public', function(req, res){
	
		res.send('public')
});
app.listen(3000);