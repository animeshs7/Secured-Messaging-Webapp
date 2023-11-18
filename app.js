var express = require('express');
var app = express();
var mysql = require('mysql');
var bodyParser = require('body-parser');
var session = require('express-session');
var bcrypt = require('bcrypt');
var crypto = require('crypto');
var globaluser = "null";
function setglobal(a) {
    globaluser = a;
};
app.set('view engine', 'ejs');

for (i = 0; i < results.length; i++) {
    const rec_paylod = Buffer.from(results[i].message, 'base64').toString('hex');
    const rec_iv = rec_paylod.substr(0, 32);
    const rec_encrypted = rec_paylod.substr(32, rec_paylod.length - 32 - 32);

    const rec_auth_tag = rec_paylod.substr(rec_paylod.length - 32, 32);
    console.table({
        reciv: rec_iv,
        rec_encrypted: rec_encrypted,
        rec_auth_tag: rec_auth_tag
    });
    try {
        const decipher = crypto.createDecipheriv(
            'aes-256-gcm',
            Buffer.from(arunSharedKey, 'hex'),
            Buffer.from(rec_iv, 'hex')
        );
        decipher.setAuthTag(Buffer.from(rec_auth_tag, 'hex'));
        // decipher.setAuthTag(crypto.randomBytes(16));
        let decrypted = decipher.update(rec_encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        console.log(decrypted);
        results[i].message = decrypted;
    } catch (error) {
        console.log(error.message);
    }
}
res.render("view_message.ejs", { data: results });

app.get("/login/send_message", function (req, res) {
    res.render("send_message.ejs", { name: globaluser });
})
app.post("/send", function (req, res) {
    var user_to = req.body.username;
    var MESSAGE = req.body.message;
    const IV = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256- gcm', Buffer.from(himanshuSharedKey, 'hex'), IV);
    let encrypted = cipher.update(MESSAGE, 'utf8', 'hex')
    encrypted += cipher.final('hex')
    const auth_tag = cipher.getAuthTag().toString('hex');
    console.table({
        IV: IV.toString('hex'),
        encrypted: encrypted,
        auth_tag: auth_tag
        });
    const payload = IV.toString('hex') + encrypted + auth_tag
    const payload64 = Buffer.from(payload, 'hex').toString('base64');
    console.log(payload64);
    MESSAGE = payload64;
    connection.query("INSERT INTO messages VALUES(?, ?, ?)", [globaluser, user_to, MESSAGE], function (error, results) {
        if (error) throw error;
        else {
            console.log(globaluser);
            console.log("MESSAGE SENT!");
              res.send("Message sent!!");
        }
    })
})
app.listen(8080, function () {
    console.log("connected on localhost:8080")
})