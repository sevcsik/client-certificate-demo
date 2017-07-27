// -----------------------------------------------------
// title: Generating and Installing Client Certificates
// -----------------------------------------------------

"use strict"

const express = require('express')
const flash = require('express-flash')
const bodyParser = require('body-parser')
const session = require('express-session')
const fs = require('fs')
const https = require('https')
const { exec } = require('child_process')
const { createHash } = require('crypto')

const httpsOpts = { key: fs.readFileSync('server_key.pem')
                  , cert: fs.readFileSync('server_cert.pem')
                  , requestCert: true
                  , rejectUnauthorized: false
                  , ca: [ fs.readFileSync('server_cert.pem') ]
                  }

const app = express()
app.use(bodyParser.urlencoded({ extended: true }))
app.use(session({ secret: 'secret', resave: false, saveUninitialized: false }))
app.use(flash())

class Cert {
	constructor(uid, userAgentString) {
		this.hash = null
		this.issuedAt = null
		this.p12 = null
		this.serial = Math.floor(Math.random() * 100000000)
		this.userAgent = userAgentString
		this.revoked = false
		this.uid = uid
	}

	generate() {
		return new Promise((resolve, reject) => {
			let key
			const keygen = exec('openssl genrsa 4096', (error, stdout, stderr) => key = stdout)
			const req = exec(`cat | openssl req -key /dev/stdin -new -nodes -days 365 -subj /CN=${this.uid}`)
			const x509 = exec(`openssl x509 -req -CA server_cert.pem -CAkey server_key.pem -set_serial ${this.serial} -days 365`, (error, stdout, stderr) => {
				const cert = stdout
				const pkcs12 = exec(`openssl pkcs12 -export -clcerts -nodes -password pass: -name "${this.uid}"`, { encoding: null }, (error, stdout, stderr) => {
					this.p12 = stdout

					const hash = createHash('sha1')
					hash.update(stdout)
					this.hash = hash.digest('hex')
					resolve(this.hash)
				})
				pkcs12.stdin.write(key + cert)
				pkcs12.stdin.end()
			})

			keygen.stdout.pipe(req.stdin)
			req.stdout.pipe(x509.stdin)
		})
	}
}

const db = [ { uid: 'Alice', password: 'password', certs: [], data: 'such sensitive data' }
           , { uid: 'Bob', password: 'letmein', certs: [], data: 'even more sensitive data' }
           ]

const requireAuthentication = level => (req, res, next) => {
	if (req.session.authentication === level) {
		const user = db.find(user => user.uid === req.session.uid)
		if (user) {
			req.user = user
			next()
		} else {
			req.flash('Your session is invalid, please log in again.')
			req.session.destroy()
			res.redirect('/password-login')
		}
	} else if (req.session.authentication === 'half' && level === 'full') {
		res.redirect('/verify-certificate')
	} else {
		res.redirect('/password-login')
	}
}

app.get('/password-login', (req, res) => {
	res.send(`
		<p>${req.flash('error') || ''}</p>
		<form method="POST">
			<p><input name="username" placeholder="username"></p>
			<p><input name="password" type="password" placeholder="password"></p>
			<p><input type="submit" value="Log in"</p>
		</form>
	`)
})

app.post('/password-login', (req, res) => {
	const { username, password } = req.body
	const user = db.find(user => user.uid === username)

	if (user && user.password === password) {
		req.session.authentication = 'half'
		req.session.uid = username
		res.redirect('/')
	} else {
		req.flash('error', 'Invalid username/password')
		res.redirect('/password-login')
	}
})

app.get('/verify-certificate', (req, res) => {
	try {
		const cert = req.client.getPeerCertificate()
		if (!cert || !req.client.authorized) throw 'No valid certificate'
		const user = db.find(user => user.uid === cert.subject.CN)
		if (!user) throw `No such user: ${cert.subject.CN}`
		const certEntry = user.certs.find((certEntry) => parseInt(cert.serialNumber, 16) === certEntry.serial)
		if (!certEntry) throw `Unknown certificate: ${cert.subject.CN} [${cert.hash}]`
		if (certEntry.revoked) throw `Certificate has been revoked: ${cert.subject.CN} [${cert.hash}]`
		req.session.authentication = 'full'
		req.session.uid = cert.subject.CN
		certEntry.p12 = null
		res.redirect('/')
	} catch (errorMessage) {
		req.flash('error', errorMessage)
		res.redirect('/create-pkcs12')
	}
})

app.get('/create-pkcs12', requireAuthentication('half'), (req, res) => {
	res.send(`We sent an email to download your client certificate.
	          Open the link <strong>in this browser</strong> to download the certificate, and add import it.`)

	const cert = new Cert(req.user.uid, req.headers['User-Agent'])
	req.user.certs.push(cert)
	cert.generate().then(hash => {
		console.log(`Certificate download URL: https://localhost:9999/download-pkcs12/${hash}/certificate.p12`)
	})
})

app.get('/download-pkcs12/:hash/certificate.p12', requireAuthentication('half'), (req, res) => {
	const cert = req.user.certs.find(cert => cert.hash === req.params.hash)
	if (cert) {
		if (cert.p12) {
			res.type('application/x-pkcs12')
			res.send(cert.p12)
		} else {
			res.send(`You have already used this key, please creaate a new one.
				      <a href="/create-pkcs12">Click here to create a new certificate</a>.`)
		}
	} else {
		res.send(`The download link is invalid.
		          <a href="/create-pkcs12">Click here to create a new certificate</a>.`)
	}
})

app.get('/', requireAuthentication('full'), (req, res) => {
	res.send(`Hello ${req.user.uid}, here's your data: ${req.user.data}`)
})

https.createServer(httpsOpts, app).listen(9999)
