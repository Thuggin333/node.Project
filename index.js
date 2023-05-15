import express from 'express';
import session from 'express-session';
import fs from 'fs';
import path from 'path';
import bcrypt from 'bcrypt';
import passport from 'passport';
import passportLocal from 'passport-local';

const users = JSON.parse(fs.readFileSync('data.json'));


const app = express();
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave:false,
    saveUninitialized: false
}))
app.use(express.static("views"))
app.use(express.json())
app.use(express.urlencoded({extended:true}))
app.use(passport.initialize())
app.use(passport.session())

passport.use(new passportLocal.Strategy({
    usernameField:"email"
},async(email,password,done)=>{
    const user = users.find(user => user.email === email)
    if (user === undefined) {
        return done(null,null,{message:"User not found"})
    }
    if (await bcrypt.compare(password,user.password)) {
        return done(null,user)
    }
    done(null,null,{message:"incorrect password"})
}))
passport.serializeUser((user,done)=>{
    done(null,user.id)

})
passport.deserializeUser((id ,done)=>{
    done(null,users.find(user => user.id === id))
})

app.get("/register",checkNotAuthentication, (req, res) => {
    res.sendFile(path.resolve("views/register.html"))
})
app.post("/register",async (req, res) => {
    const {name, email, password} = req.body
    const hashedPwd = await bcrypt.hash(password,10)


    const user ={
        id:`${Date.now()}_${Math.random()}`,
        name,
        email,
        password:hashedPwd
    } ;
    const users = JSON.parse(fs.readFileSync('data.json'));
    users.push(user);
    fs.writeFileSync('data.json', JSON.stringify(users));

    res.redirect("/login")
})
app.get("/login",checkNotAuthentication, (req, res) => {
    res.sendFile(path.resolve("views/login.html"))
})
app.post("/login", passport.authenticate("local",{
    successRedirect:"/",
    failureRedirect:"/login"
}))

app.get('/',checkAuthentication, (req, res) => {

    res.sendFile(path.resolve("views/app.html"))
})

app.get("/logout", (req, res,next) => {

    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect('/login');
      });
})

function checkAuthentication(req, res,next){
    if (req.isAuthenticated() === false) {
        return res.redirect("/login")
    }
    next()
}
function checkNotAuthentication(req, res,next){
    if (req.isAuthenticated() === true) {
        return res.redirect("/")
    }
    next()
}

app.listen(process.env.PORT)

