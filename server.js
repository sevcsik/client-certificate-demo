// ------------------------------------------------------
// title: Generating and Provisioning Client Certificates
// ------------------------------------------------------

"use strict"

const express = require('express')
const flash = require('express-flash')
const bodyParser = require('body-parser')
const session = require('express-session')
const fs = require('fs')
const https = require('https')
const { exec } = require('child_process')

const httpsOpts = { key: fs.readFileSync('ssl/server_key.pem')
                  , cert: fs.readFileSync('ssl/server_cert.pem')
                  , requestCert: true
                  , rejectUnauthorized: false
                  , ca: [ fs.readFileSync('ssl/server_cert.pem') ]
                  }

const app = express()
app.use(bodyParser.urlencoded({ extended: true }))
app.use(session({ secret: 'secret', resave: false, saveUninitialized: false }))
app.use(flash())

class Cert {
	constructor(uid, userAgentString) {
		this.fingerprint = null
		this.issuedAt = new Date()
		this.p12 = null
		this.userAgent = userAgentString
		this.revoked = false
		this.uid = uid
	}

	createX509(spkac) {
		const certP = new Promise((resolve, reject) => {
			const ca = exec(`cat | openssl ca -batch -notext -spkac /dev/stdin -config ssl/openssl.cnf -subj /CN=${this.uid}`
				, (error, stdout, stderr) => {
					if (error) reject(error)
					else resolve(stdout)
				})

			ca.stdin.write('SPKAC=' + spkac.replace(/[\r\n]/g, ''))
			ca.stdin.end()
		})
		certP.then(this.getFingerprint).then(fingerprint => this.fingerprint = fingerprint)
		return certP
	}

	generatePkcs12() {
		return new Promise((resolve, reject) => {
			let key
			const keygen = exec('openssl genrsa 4096', (error, stdout, stderr) => key = stdout)
			const req = exec(`cat | openssl req -new -key /dev/stdin -batch`, (error, stdout, stderr) => console.error(stderr))
			const ca = exec(`cat | openssl ca -in /dev/stdin -config ssl/openssl.cnf -batch -subj /CN=${this.uid}`
				, (error, stdout, stderr) => {
					if (error) reject(error)
					else resolve({ key, cert: stdout })
				})

			keygen.stdout.pipe(req.stdin)
			req.stdout.pipe(ca.stdin)
		}).then(({ key, cert }) => Promise.all(
			[new Promise((resolve, reject) => {
				const pkcs12 = exec(`openssl pkcs12 -export -clcerts -nodes -password pass: -name "${this.uid}"`
					, { encoding: null }
					, (error, stdout, stderr) => {
						if (error) reject(error)
						else {
							resolve()
							this.p12 = stdout
						}
					})

				pkcs12.stdin.write(key + cert)
				pkcs12.stdin.end()
			}), this.getFingerprint(cert)]
		)).then(([_, fingerprint]) => this.fingerprint = fingerprint)
	}

	getFingerprint(cert) {
		return new Promise((resolve, reject) => {
			const x509 = exec(`openssl x509 -fingerprint -out /dev/null`, (error, stdout, stderr) => {
				if (error) reject(error)
				else resolve(stdout.split('=')[1].trim())
			})

			x509.stdin.write(cert)
			x509.stdin.end()
		})
	}
}

const db = [ { uid: 'Alice', password: 'password', certs: [], data: 'such sensitive data' }
           , { uid: 'Bob', password: 'letmein', certs: [], data: 'even more sensitive data' }
           ]

const requireAuthentication = level => (req, res, next) => {
	const user = db.find(user => user.uid === req.session.uid)
	req.user = user
	if (level === 'half' && req.session.authentication === level) {
		next()
	} else if (level === 'full' && req.session.authentication === level) {
		const cert = user.certs.find(cert => cert.fingerprint === req.session.fingerprint)
		if (cert && !cert.revoked) {
			next()
		} else {
			req.flash('error', 'Your certificate has been revoked, delete your certificate and log in again.')
			req.session.authentication = null
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
		${req.flash('error') || ''}
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
		const certEntry = user.certs.find((certEntry) => certEntry.fingerprint === cert.fingerprint)
		if (!certEntry) throw `Unknown certificate: ${cert.subject.CN} [${cert.serialNumber}]`
		req.session.authentication = 'full'
		req.session.uid = cert.subject.CN
		req.session.fingerprint = cert.fingerprint
		certEntry.p12 = null
		res.redirect('/')
	} catch (errorMessage) {
		req.flash('error', errorMessage)
		res.redirect('/create-pkcs12')
	}
})

app.get('/create-x509', requireAuthentication('half'), (req, res) => {
	const challenge = Math.floor(Math.random() * 100000000)
	res.send(`<form method="POST">
	             <keygen name="pubkey" keytype="RSA" challenge="${challenge}">
	             <input type="submit" value="Create certificate">
	          </form>`)
})

app.post('/create-x509', requireAuthentication('half'), (req, res) => {
	const cert = new Cert(req.user.uid, req.headers['user-agent'])
	req.user.certs.push(cert)
	const x509 = cert.createX509(req.body.pubkey).then((x509) => {
		res.type('application/x-x509-user-cert')
		res.send(x509)
	}, error => res.status(500).send(error))
})

app.get('/create-pkcs12', requireAuthentication('half'), (req, res) => {
	res.send(`You successfully logged in, but you don't have a valid certificate installed in this browser.
	          <form method="POST"><input type="submit" value="Create certificate"></form>`)
})

app.post('/create-pkcs12', requireAuthentication('half'), (req, res) => {
	const cert = new Cert(req.user.uid, req.headers['user-agent'])
	req.user.certs.push(cert)
	cert.generatePkcs12().then(fingerprint => {
		console.log(`Certificate download URL: https://localhost:9999/download-pkcs12/${fingerprint}/certificate.p12`)
		res.send(`We sent an email to download your client certificate.
				  Open the link <strong>in this browser</strong> to download the certificate, and add import it.`)
	}, (error) => res.status(500).send(error.message))

})

app.get('/download-pkcs12/:fingerprint/certificate.p12', requireAuthentication('half'), (req, res) => {
	const cert = req.user.certs.find(cert => cert.fingerprint === req.params.fingerprint)
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

app.get('/revoke-certificate', requireAuthentication('full'), (req, res) => {
	const certs = req.user.certs.filter(cert => !cert.revoked)
	const options = certs.map(cert => `<option value="${cert.fingerprint}">
	                                       Issued at ${cert.issuedAt} to ${cert.userAgent}
	                                   </option>`)
	                     .concat('\n')

	res.send(`Hi ${req.user.uid}, please select a certificate to revoke:
	          <form method="POST">
	             <select name="certificate">${options}</select>
	             <input type="submit" value="Revoke">
	          </form>`)
})

app.post('/revoke-certificate', requireAuthentication('full'), (req, res) => {
	const fingerprint = req.body.certificate
	if (fingerprint) {
		const cert = req.user.certs.find(cert => cert.fingerprint === fingerprint)
		if (cert) {
			cert.revoked = true
			if (cert.fingerprint === req.session.fingerprint) {
				req.session.destroy()
				res.redirect('/')
			} else {
				res.send('The certificate has been revoked. <a href="/">Go back</a>')
			}
		} else {
			res.status(404).send('No such certificate')
		}
	} else {
		res.status(400).send('Bad request')
	}
})

app.get('/', requireAuthentication('full'), (req, res) => {
	res.send(`Hello ${req.user.uid}, here's your data: ${req.user.data}
	          <a href="/revoke-certificate">Revoke certificates</a>`)
})

https.createServer(httpsOpts, app).listen(9999)

// Sources
// =======
// - ["Alternatives to HTML's deprecated <keygen> for client certs?" on Security StackExchange](https://security.stackexchange.com/questions/106257/alternatives-to-htmls-deprecated-keygen-for-client-certs)
// - [Javascript Crypto on MDN](https://developer.mozilla.org/en-US/docs/Archive/Mozilla/JavaScript_crypto)
// - [Intent to Remove: Keygen on blink-dev](https://groups.google.com/a/chromium.org/forum/#!msg/blink-dev/z_qEpmzzKh8/BH-lkwdgBAAJ
// - [Old Web Crypto API on W3C](https://groups.google.com/a/chromium.org/forum/#!msg/blink-dev/z_qEpmzzKh8/BH-lkwdgBAAJ)
// - ["How do you pipe a long string to /dev/stdin via child_process.spawn() in Node.js?" on javacms](http://www.javacms.tech/questions/408044/how-do-you-pipe-a-long-string-to-dev-stdin-via-child-process-spawn-in-node-js)
// - [PKI.js](https://pkijs.org/)
// - ["Removing keygen from HTML" thread on W3C's www-tag list](https://lists.w3.org/Archives/Public/www-tag/2016May/0006.html)
// - [Keygen and Client Certificates](https://w3ctag.github.io/client-certificates/)
// - [HOWTO set up a small server](http://chschneider.eu/linux/server/openssl.shtml)
