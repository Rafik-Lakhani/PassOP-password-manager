const http = require('http');
const nodemailer=require("nodemailer")
const dotenv = require("dotenv");
dotenv.config();


const httpserver = http.createServer((req, res) => {
  let body = '';

  req.on('data', (chunk) => {
    body += chunk.toString();
  });

  req.on('end', async() => {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    let userdata=JSON.parse(body);
    

    const transporter = await nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 587,
      secure: false,
      auth: {
          user: process.env.SEND_EMAIL_ADDRESS,
          pass:process.env.SEND_EMAIL_PASSWORD,
      },
  });

  const info = await transporter.sendMail({
      from: '"</passOP>" <lakhanirafik111@gmail.com>', // sender address
      to: `${userdata.email}`, // list of receivers
      subject: "OTP verification", // Subject line
      text: `
    Thank you for choosing </passOP> Password Manager.

    To complete your verification process, please use the One-Time Password (OTP) provided below. This code is valid for the next 1 minutes.

    Your OTP Code: ${userdata.otp}

    If you did not request this code, please ignore this email or contact our support team immediately.

    For your security, do not share this OTP with anyone.

    Thank you,
    </passOP> Support Team
      `, // plain text body
  })
    res.end("done");
  });
  

});

module.exports=httpserver;
