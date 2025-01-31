const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const CryptoJS = require("crypto-js")
const userdb = require("./model/userlogindb");
const pwdb = require("./model/pwdb");
const http = require("http");
const httpserver = require("./httpserver");
const dotenv = require("dotenv");
const path = require('path');

httpserver.listen(8000,function(){console.log("http server running in 8000 port")})



dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000 ;
var userdata = {};
var userotp = {};
var timeout = false;
app.use(cookieParser());
app.set("view engine", "ejs");
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));


app.get("/", async (req, res) => {
    if (req.cookies.token) {
        let user
        let userem = jwt.verify(req.cookies.token, "rafik");
        if (typeof (userem) === "string") {
            user = await userdb.findOne({ email: userem });
        }
        else {
            user = await userdb.findOne({ email: userem.email });
        }
        let dt = await pwdb.find({ userid: user._id }, { _id: 0, userid: 0, pwdate: 0 });
        let pwarr = dt.map((element) => {
            pw = CryptoJS.AES.decrypt(element.sitepw, 'userpw');
            element.sitepw = pw.toString(CryptoJS.enc.Utf8);
            return element
        });
        res.render("index", { email: user.email, data: pwarr })
    }
    else {
        res.render("index", { email: "", data: [] });
    }
})


app.post("/save", async (req, res) => {
    try {
        let usersv;
        var userem = jwt.verify(req.cookies.token, "rafik");
        if (typeof (userem) === "string") {
             usersv = await userdb.findOne({ email: userem });
        }
        else {
             usersv = await userdb.findOne({ email: userem.email })
        }
        let store = CryptoJS.AES.encrypt(req.body.sidepw, 'userpw').toString();
        let dmge = CryptoJS.AES.decrypt(store, 'userpw');
        let ltw = dmge.toString(CryptoJS.enc.Utf8);
        await pwdb.create({
            userid: usersv._id,
            siteurl: req.body.sideurl,
            usernm: req.body.sideun,
            sitepw: store,
        })

        res.redirect("/");
    }
    catch (err) {
        // console.log(err);
        // res.send("<script>please login</script>");
        res.redirect("/");
    }

})

function otpgenerator() {
    return Math.floor(100000 + Math.random() * 900000);
}




async function emailsender(email,otp){
    const request=http.request({method: 'POST',
        path: '/',
        headers: {
            'Content-Type': 'application/json'
          },
        hostname: 'localhost',
        port: 8000,},(res)=>{
            res.on('data',(value)=>{
            })
    
            res.on('end', () => {
            });
        });
    
        request.on('error', (error) => {
            console.log("error");
        });
       let useremotp=JSON.stringify({ email: `${email}`, otp: `${otp}` });
        request.write(useremotp)
        request.end();
        return 0;
}

app.get("/register", (req, res) => {
    res.render("register");
})


app.post("/registeruser", async (req, res) => {
    em = req.body.email;
    timeout = false;
    let useralldata = await userdb.findOne({ email: em });;
    if (useralldata != null) {
        res.redirect("/register");
    }
    else {
        userdata[em] = req.body;
        userotp[em] = otpgenerator();
        res.render("verify", { email: em, from: "" });

        // mail request code here
        await emailsender(em,userotp[em]);

        setTimeout(() => {
            delete userdata[em];
            delete userotp[em];
            timeout = true;
        }, 60000);
        console.log(userotp[em]);
    }
})

app.post("/verifyemail", async (req, res) => {
    if (timeout == false) {
        var rguser = req.query.em;
        let data = userdata[rguser];
        if (req.body.otp == userotp[rguser]) {
            const salt = await bcrypt.genSalt(10);
            const hash = await bcrypt.hash(data.password, salt);

            await userdb.create({
                username: data.name,
                email: data.email,
                password: hash
            })
            delete userdata[rguser];
            delete userotp[rguser];
            token = jwt.sign({ email: rguser }, "rafik")
            res.cookie("token", token);
            res.redirect("/")
            timeout = true;
        }
        else {
            delete userdata[rguser];
            delete userotp[rguser];
            res.redirect("/register");
        }
    }

    else {
        delete userdata[rguser];
        delete userotp[rguser];
        res.redirect("/register");
    }
})


app.get("/login", (req, res) => {
    res.render("login", { form: "" });
})

app.post("/loginuser", async (req, res) => {
    usemail = req.body.email;
    timeout = false;
    let pwuser = await userdb.findOne({ email: usemail });
    userdata[usemail] = req.body;
    userotp[usemail] = otpgenerator();
    console.log(userotp[usemail]);

    if (pwuser != "undefine") {
        bcrypt.compare(req.body.password, pwuser.password, async(err, result) => {
            if (result) {
                res.render("verify", { email: usemail, from: "login" });
                await emailsender(usemail,userotp[usemail]);
                setTimeout(() => {
                    delete userdata[usemail];
                    delete userotp[usemail];
                    timeout = true;
                }, 60000);
            }
            else {
                delete userdata[usemail];
                delete userotp[usemail];
                res.redirect("/login")
            }
        })
    }
    else {
        res.redirect("/login")
        delete userdata[usemail];
        delete userotp[usemail];
    }

})

app.post("/loginemailverify", async (req, res) => {
    em = req.query.email;
    if (timeout == false) {
        if (req.body.otp == userotp[em]) {
            delete userdata[em];
            delete userotp[em];
            token = jwt.sign(em, "rafik")
            res.cookie("token", token);
            res.redirect("/")
        }
        else {
            delete userdata[em];
            delete userotp[em];
            res.redirect("/login");
        }
        timeout = true;
    }
    else {
        delete userdata[em];
        delete userotp[em];
        res.redirect("/login");
    }
})
app.get("/tryagain", (req, res) => {
    res.redirect("/")
})

app.get("/logout", (req, res) => {
    res.clearCookie("token");
    res.redirect("/");
})


app.get("/delete/:usernm", async (req, res) => {
    await pwdb.findOneAndDelete({ usernm: req.params.usernm })
    res.redirect("/")
})


app.get("/profile/:userem", async (req, res) => {
    let user = await userdb.findOne({ email: req.params.userem });
    res.render("profile", { name: user.username, email: user.email, date: user.joindate })
})


app.listen(PORT, () => console.log("server running in port"+PORT));