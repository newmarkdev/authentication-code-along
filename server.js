import express from 'express'
import cors from 'cors'
import mongoose from 'mongoose'
import listEndpoints from 'express-list-endpoints'
import crypto from 'crypto'
import bcrypt from 'bcrypt-nodejs'

const mongoUrl = process.env.MONGO_URL || "mongodb://localhost/auth"
// eslint-disable-next-line max-len
mongoose.connect(mongoUrl, { useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true })
mongoose.Promise = Promise

const User = mongoose.model('User', {
    name: {
      type:String,
      unique: true
    },
    email: {
      type:String,
      unique: true
    },
    password: {
      type:String,
      unique: true
    },
    accessToken: {
      type:String,
      default: ()=> crypto.randomBytes(128).toString('hex')
    }
})

const authenticateUser = async (req, res, next) => {
  const user = await User.findOne({accessToken: req.header('Autherization')});
  if(user){
    req.user = user;
    next();
  }else {
  res.status(400).json({loggedOut:true});
  }
}

const port = process.env.PORT || 8080
const app = express()

// Add middlewares to enable cors and json body parsing
app.use(cors())
app.use(express.json())

// Start defining your routes here
app.get('/', (req, res) => {
  res.send(listEndpoints(app))
})

app.post(' ', (req, res) =>{
  try {
  const {name, email, password} = req.body;
  // Do not store plain text passwords
  const user = new User({name, email, password: bcrypt.hashSync(password)});
  user.save();
  res.status(201).json({id: user._id, accessToken: user.accessToken});
  }catch(err){
    res.status(400).json({message: 'Could not create user', errors: err.errors});
 
  }
});

app.get('/secrets',authenticateUser);
app.get('/secrets', (req, res) => {
  res.json({secret: 'this is a secret message!'})
})

app.post('/sessions', async (req, res) => {
  const user = await User.findOne({email: req.body.email});
  if(user && bcrypt.compareSync(req.body.password, user.password)) {
    res.json({userId: user._id, accessToken: user.accessToken});
  }else {
    res.json({notFound: true});
  }
})

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`)
})
