const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const CryptoJS = require("crypto-js")
const userdb = require("./model/userlogindb");
const pwdb = require("./model/pwdb");
const dotenv = require("dotenv");
const path = require('path');
const otpModel = require('./model/Otpdb');
const nodemailer = require('nodemailer');




dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;
app.use(cookieParser());
app.set("view engine", "ejs");
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));


app.get("/", async (req, res) => {
    if (req.cookies.token) {
        var userData;
        const userem = jwt.verify(req.cookies.token, process.env.JWT_SECRET);
        if (typeof (userem) === "string") {
            userData = await userdb.findOne({ email: userem });
        }
        else {
            userData = await userdb.findOne({ email: userem.email });
        }
        let dt = await pwdb.find({ userid: userData._id }, { userid: 0, pwdate: 0 });
        let pwarr = dt.map((element) => {
            pw = CryptoJS.AES.decrypt(element.sitepw, 'userpw');
            element.sitepw = pw.toString(CryptoJS.enc.Utf8);
            return element
        });
        res.render("index", { email: userData.email, data: pwarr })
    }
    else {
        res.render("index", { email: "", data: [] });
    }
})


app.post("/save", async (req, res) => {
    try {
        let usersv;
        var userem = jwt.verify(req.cookies.token, process.env.JWT_SECRET);
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
        console.log(err);
        // res.send("<script>please login</script>");
        res.redirect("/");
    }

})

function otpgenerator() {
    return Math.floor(100000 + Math.random() * 900000);
}




async function emailsender(email, otp) {
    const transporter = await nodemailer.createTransport({
        host: "smtp.gmail.com",
        port: 465,
        secure: true,
        auth: {
            user: process.env.SEND_EMAIL_ADDRESS,
            pass: process.env.SEND_EMAIL_PASSWORD,
        },
    });
    const info = await transporter.sendMail({
        from: '"</passOP>" <lakhanirafik111@gmail.com>', // sender address
        to: `${email}`, // list of receivers
        subject: "OTP verification", // Subject line
        text: `
      Thank you for choosing </passOP> Password Manager.
  
      To complete your verification process, please use the One-Time Password (OTP) provided below. This code is valid for the next 1 minutes.
  
      Your OTP Code: ${otp}
  
      If you did not request this code, please ignore this email or contact our support team immediately.
  
      For your security, do not share this OTP with anyone.
  
      Thank you,
      </passOP> Support Team
        `, // plain text body
    });
    return info;
}

app.get("/register", (req, res) => {
    if (req.query.message) {
        res.render("register", { message: req.query.message });
    }
    else {
        res.render("register", { message: "" });
    }
})


app.post("/registeruser", async (req, res) => {
    em = req.body.email;
    let useralldata = await userdb.findOne({ email: em });;
    if (useralldata != null) {
        res.redirect("/register?message=Email already exists");
    }
    else {
        const otp = otpgenerator();
        await otpModel.create({ email: em, otp: otp });
        var info = await emailsender(em, otp);
        if (info) {
            res.render("verify", { email: em, from: "", userdata: req.body });
        } else {
            res.redirect("/register?message=Server error please try again");
        }
    }
})

app.post("/verifyemail", async (req, res) => {
    let otp = await otpModel.findOne({ email: req.body.email }).sort({ createdDate: -1 });
    if (otp) {
        if (otp.expiryDate != otp.createdDate + 60000) {
            if (otp.otp == req.body.otp) {
                const salt = await bcrypt.genSalt(10);
                const hash = await bcrypt.hash(req.body.password, salt);
                let user = await userdb.create({ username: req.body.username, email: req.body.email, password: hash });
                if (user) {
                    let token = jwt.sign(req.body.email, process.env.JWT_SECRET);
                    res.cookie("token", token);
                    res.redirect("/");
                }
                else {
                    res.redirect("/register?message=Server error please try again");
                }
            }
        } else {
            res.redirect("/register?message=OTP expired");
            return false;
        }
    }
    else {
        res.redirect("/register?message=Email not found");
    }
})


app.get("/login", (req, res) => {
    if (req.query.message) {
        res.render("login", { message: req.query.message, form: "" });
    } else {
        res.render("login", { form: "", message: "" });
    }
})

app.post("/loginuser", async (req, res) => {
    const useremail = req.body.email;
    let pwuser = await userdb.findOne({ email: useremail });
    const otp = otpgenerator();

    if (pwuser != "undefine") {
        bcrypt.compare(req.body.password, pwuser.password, async (err, result) => {
            if (result) {
                let info = await emailsender(useremail, otp);
                if (info) {
                    await otpModel.create({ email: useremail, otp: otp });
                    res.render("verify", { email: useremail, password: req.body.password, from: "login" });
                } else {
                    res.redirect("/login?message=Server error please try again");
                    return false;
                }
            }
            else {
                res.redirect("/login?message=Invalid password");
                return false;
            }
        })
    }
    else {
        res.redirect("/login?message=Email not found");
        return false;
    }

})

app.post("/loginemailverify", async (req, res) => {
    const email = req.query.email;
    const otp = await otpModel.findOne({ email: email }).sort({ createdDate: -1 });
    if (otp) {
        if (otp.expiryDate != otp.createdDate + 60000) {
            if (otp.otp == req.body.otp) {
                let token = jwt.sign(email, process.env.JWT_SECRET);
                res.cookie("token", token);
                res.redirect("/");
            } else {
                res.redirect("/login?message=Invalid OTP");
                return false;
            }
        } else {
            res.redirect("/login?message=OTP expired");
            return false;
        }
    } else {
        res.redirect("/login?message=Email not found");
        return false;
    }
})
app.get("/tryagain", (req, res) => {
    res.redirect("/")
})

app.get("/logout", (req, res) => {
    res.clearCookie("token");
    res.redirect("/");
})


app.get("/delete/:passwordId", async (req, res) => {
    await pwdb.findOneAndDelete({ _id: req.params.passwordId });
    res.redirect("/")
})

app.get("/edit/:passwordId", async (req, res) => {
    const password = await pwdb.findOne({ _id: req.params.passwordId });
    if (!password) return res.redirect("/");
    password.sitepw = CryptoJS.AES.decrypt(password.sitepw, 'userpw').toString(CryptoJS.enc.Utf8);
    res.render("edit", { password: password });
});

app.post("/edit/:passwordId", async (req, res) => {
    // check if this password match with the user
    const userem = jwt.verify(req.cookies.token, process.env.JWT_SECRET);
    const user = await userdb.findOne({ email: userem });
    const password = await pwdb.findOne({ _id: req.params.passwordId });
    if (!user) return res.redirect("/?message=Invalid user");
    if (user._id.toString() !== password.userid.toString()) return res.redirect("/?message=Invalid password");
    if (!password) return res.redirect("/");
    password.siteurl = req.body.siteurl;
    password.usernm = req.body.sideusername;
    password.sitepw = CryptoJS.AES.encrypt(req.body.sitepwd, 'userpw').toString();
    await password.save();
    res.redirect("/");
});


app.get("/profile/:userem", async (req, res) => {
    let user = await userdb.findOne({ email: req.params.userem });
    res.render("profile", { name: user.username, email: user.email, date: user.joindate })
})




app.listen(PORT, () => console.log("server running in port" + PORT));