'use strict';
const routes = require('./Routes.js')
const auth = require('./Auth.js')
const express     = require('express');
const bodyParser  = require('body-parser');
const fccTesting  = require('./freeCodeCamp/fcctesting.js');

const app = express();
const cors = require('cors')
const passport = require('passport');
const session = require('express-session')

const ObjectId = require('mongodb').ObjectID
const mongo = require('mongodb').MongoClient
const bcrypt = require('bcrypt')
const LocalStrategy=require('passport-local')
fccTesting(app); //For FCC testing purposes
app.use('/public', express.static(process.cwd() + '/public'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.set('view engine','pug')
//https://stackoverflow.com/questions/29111571/passports-req-isauthenticated-always-returning-false-even-when-i-hardcode-done
app.use(session({
secret:process.env.SESSION_SECRET,
  resave:true,
  saveUnitialized:true
}))
app.use(passport.initialize())
app.use(passport.session())

 

function ensureAuthenticated(req, res, next){
  //console.log('route:: /profile')
  //console.log(req.isAuthenticated())
if (req.isAuthenticated()){
return next()
}
res.redirect('/')
}

//app.use(passport.authenticate('local'))

mongo.connect(process.env.DATABASE, (err, db)=>{
if(err){
console.log('Database error: '+err)

} else {
console.log('Successful database connection')
//}})
routes(app,db)
  auth(app,db)

passport.serializeUser((user,done)=>{
done(null, user._id)
})

passport.deserializeUser((id,done)=>{
db.collection('users').findOne(
  {_id: new ObjectId(id)},
    (err, doc) =>{done(null, doc)}  )
})

passport.use(new LocalStrategy(function(username, password, done){
db.collection('users').findOne({username:username},function(err, user){
console.log('User '+ username+ ' attempted to log in .')
  if (err){return done(err)}
  if(!user){return done(null, false)}
  //if (password !== user.password) { return done(null, false)}
  if(!bcrypt.compareSync(password, user.password)){return done(null, false)}
  //console.log("... user verified>>" +user.username)
  return done(null, user)
    
})//findOne


}))

app.route('/')
  .get((req, res) => {
    //res.sendFile(process.cwd() + '/views/index.html');
  res.render(process.cwd()+'/views/pug/index.pug', {title:'Home Page',message:'Please login', showLogin:true, showRegistration: true})
  });

  app.route('/login')
  .post(passport.authenticate('local',{failureRedirect:'/'}),function(req,res){
  res.redirect('/profile')
  })
  
  app.route('/profile')
  .get(ensureAuthenticated,(req,res) =>{
    //console.log("sending to /profile")
  res.render(process.cwd()+'/views/pug/profile',{username:req.user.username})
  
  })
  
  app.route('/logout').get((req,res)=>{
    req.logout()
    res.redirect('/')
  })
  
  
  //////////////////////////////////////////////
  app.route('/register')
  .post((req,res,next)=>{
    
    db.collection('users').findOne({username:req.body.username}, function(err,user){
      //console.log('determining if usr exist |' +err + "|"+ user)
      if(err) {next(err)}
      else if (user) {res.redirect('/')}
      else {
        var hash = bcrypt.hashSync(req.body.password,12)
        db.collection('users').insertOne(
          {username:req.body.username,
           //password:req.body.password
           password:hash
          }, (err,doc) => {
            if(err) {res.redirect('/')}
            else {next(null, user)}
          }
        )//insertOne
      }
    }
  )//findOne
  
  
  },passport.authenticate('local', {successRedirect: '/profile', failureRedirect:'/'}), function(req,res,next){
    //console.log("....... passportAuthenticating & redirecting to profile")
    //console.log(req.isAuthenticated())
  //  res.redirect('/profile')
  }
       ) //post
  
  app.use((req, res, next) => {
  res.status(404)
    .type('text')
    .send('Not Found');
});
  
app.listen(process.env.PORT || 3000, () => {
  console.log("Listening on port " + process.env.PORT);
});

}})



