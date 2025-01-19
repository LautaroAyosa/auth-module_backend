// /utils/sendEmail.js
const nodemailer = require('nodemailer');

async function sendEmail(to, subject, text) {
  try {
    const transporter = nodemailer.createTransport({
      host: process.env.MAIL_HOST,
      port: Number(process.env.MAIL_PORT),
      secure:  true, // or true for 465
      auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASS
      }
    });

    await transporter.sendMail({
      from: `"${process.env.APP_NAME}" <${process.env.MAIL_USER}>`,
      to,
      subject,
      text
    });
  } catch (err) {
    console.error(err);
    throw new Error('Email sending failed');
  }
}

module.exports = sendEmail;
