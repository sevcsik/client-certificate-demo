// -----------------------------------------------------
// title: Generating and Installing Client Certificates
// -----------------------------------------------------

const express = require('express')
const passport = require('passport')
const fs = require('fs')
const https = require('https')
const LocalStrategy = require('passport-local').Strategy
const ClientCertStrategy = require('passport-client-cert').Strategy

const opts = { key: fs.readFileSync('server_key.pem')
             , cert: fs.readFileSync('server_cert.pem')
             , requestCert: true
             , rejectUnauthorized: false
             , ca: [ fs.readFileSync('server_cert.pem') ]
             }

const app = express()

// To be able to revoke certificates, we need to keep a list of the issued certificates for every user. The serial
// number identifies a certificate (by definition, the serial number needs to be unique inside a CA -- us). We store
// the creation date and user agent which requested the certificate, to help the users to identify the certificates
// later.
class CertEntry {
	constructor(cert, userAgentString) {
		this.serialNumber = cert.serialNumber
		this.issuedAt = cert.valid_from
		this.userAgent = userAgentString
		this.revoked = false;
	}
}

// For the sake of brevity, we use a dead simple, in-memory object to store our credentials and our "sensitive data". 
// This is dumb and insecure (we store passwords in plain text!), so don't even think about using something like this
// in production!
const db = { 'Alice': { pw: 'password', certs: [], data: 'such sensitive data' }
           , 'Bob': { pw: 'letmein', certs: [], data: 'even more sensitive data' }
           }

// Configure passport to use our dummy "database":
passport.serializeUser((user, done) => done(user.uid))
passport.deserializeUser((uid, done) => done(db[uid]))

// Then set up a simple password-based authentication strategy. Users will have to log in the old-fashioned way if they
// don't have their client certificate installed yet.
passport.use(new LocalStrategy((uid, pw, done) => done(null, db[uid].pw === pw ? db[uid] : false)))
app.get('/password-login', (req, res) => {
	res.send(`
		<form method="POST">
			<p><input name="username" placeholcer="username"></p>
			<p><input name="password" type="password" placeholder="password"></p>
			<p><input type="submit" value="Log in"</p>
		</form>
	`)
})

// Add an endpoint for the password authentication. When the password login is successful, we don't give user access to
// the sensitive data yet, instead we redirect them to a page when they can request a new certificate.
app.post('/password-login', passport.authenticate('local', { successRedirect: '/install-certificate'
                                                           , failureRedirect: '/password-login' 
                                                           }))

passport.use(new ClientCertStrategy({ passReqToCallback: true }, (req, cert, done) => {
	try {
		if (!req.client.authorized || !cert.subject || !cert.subject.CN) throw 'No valid certificate supplied'
		const user = db[cert.subject.CN]
		if (!user) throw `No such user: ${cert.subject.CN}`
		const certEntry = user.certs.find((certEntry) => cert.serialNumber == certEntry.serialNumber)
		if (!certEntry) throw `Unknown certificate: ${cert.subject.CN} [${cert.serialNumber}]`
		if (certEntry.revoked) throw `Certificate has been revoked: ${cert.subject.CN} [${cert.serialNumber}]`
		done(null, user)
	} catch (errorMessage) {
		done(null, false, errorMessage)
	}
}))
app.use(passport.initialize())
app.use(passport.authenticate('client-cert', { successRedirect: '/'
                                             , failureRedirect: '/password-login'
                                             }))


https.createServer(opts, app).listen(9999)
