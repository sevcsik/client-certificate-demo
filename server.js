// ------------------------------------------------------
// title: Generating and Provisioning Client Certificates
// ------------------------------------------------------
//
// In my previous [article](https://sevdev.hu/ipns/sevdev.hu/posts/2017-07-22-authentication-using-https-client-certificates.html)
// I wrote about how to use client certificates to mutually authenticate HTTPS connections. We generated pkcs12
// certificate bundles by hand, and installed it manually to the browser. In this article, I'll explore a more realistic
// application, where client certificates are generate automatically, and installed to the users' browser.
//
// The example application (https://github.com/sevcsik/client-certificate-demo/releases/tag/chapter-2) I'll implement
// in this post will cover the following functionality:
//
// - Users can log in with a classic password login form (if they don't have a certificate)
// - They can request a certificate after log in
// - They can revoke previously issued certificates
// - They can access their "sensitive data" only if they have a valid certificate
//
// <!-- TEASER -->

// Our list of dependencies have a few additions compared to our prior version. We need the usual Express stuff to
// handle our password-base login, and `child_process` to call the OpenSSL binary.
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

// To provide the revocation functionality, we need a representation of our issued certificates. Since OpenSSL already
// provides a file-based storage for the certs, this is optional, however, storing them in a database (ideally with an
// in-memory cache) is much more performant, and will make implementing the revocation simpler.
class Cert {
	constructor(uid, userAgentString) {
// We'll put the User ID in the Common Name field of the certificate.
		this.uid = uid
// The fingerprint uniquely identifies a certificate (it's a hash based on the content of the cert). We'll use
// as an index to look up the certificates in our database.
		this.fingerprint = null
// We'll use the date of issue and the user agent requested the certificate to display the list of certificates
// on the revocation page - these two should give a clue to the user to identify a certificate.
		this.issuedAt = new Date()
		this.userAgent = userAgentString
// We store a revocation flag for every certificate. If it's true, it cannot be used to log in.
		this.revoked = false
// If we onboard the client using a PKCS#12 certificate bundle (more on that later), we need to store the
// bundle in our database until the client has been onboarded.
		this.p12 = null
	}

// Using the OpenSSL CLI
// =====================
//
// We need to define the openssl operations we will need to manage our certificates. Unfortunately there is no
// libopenssl binding for Node.js, so we'll have to settle with the command line tool. To avoid handling temporary
// files (and the security concerns they come with them), we use pipes whenever is possible. Unfortunately openssl
// doesn't follow the POSIX traditions, so we have to resort to some Linux-specific trickery to handle stdin/stdout
// correctly. We'll wrap these calls to a nice Promise-based API to confine the `child_process` clutter here.
//
// First, we need a method to get the fingerprint of a certificate. We could convert our certificates on PEM to DER and
// and calculate their hash, but since we'll depend on `openssl` anyway, it's easier to just wrap its x509 utility.
	getFingerprint(cert) {
		return new Promise((resolve, reject) => {
// We need to set the output file to `/dev/null`. otherwise it will output the certificate again.
			const x509 = exec(`openssl x509 -fingerprint -out /dev/null`, (error, stdout, stderr) => {
				if (error) reject(error)
// The fingerprint we're looking for looks like `SHA1 Fingerprint=AA:BB:CC...`, let's extract the actual hash.
				else resolve(stdout.split('=')[1].trim())
			})
// If `-in` is not specified, this command expects the certificate in it's standard input. After spawning the process,
// it will wait for an input. `stdin`, `stdout` and `stderr` are exposed as Node.js streams, so we can just write our
// PEM-endoded certificate data, and close them. Later we'll see that it's not always this simple - somethimes we have
// to use `/dev/stdin` to explicitly point an input file to the standard input as the OpenSSL CLI does not support the
// `-` notation for reading a file from `stdin`).
			x509.stdin.write(cert)
			x509.stdin.end()
		})
	}

// Generating certificates
// =======================
//
// Client-side key generation with `<keygen>`
// ------------------------------------------
// 
// The ideal way to generate a client certificate is to generate a key in the browser using the `<keygen>` element.
// This way the private key never leaves the browser, and on the server, we only have to create a certificate.
// Another benefit is that X.509 certificates (unline PKCS#12 bundles) can be automatically installed to the
// browser's key store.
//
// `<keygen>` generates an [SPKAC][spkac] string, which stands for "Signed Public Key and Challenge". It contains
// the matching public key the browser generated, and a challenge that is signed with that key. We will provide the
// challenge string as an attribute to the element when we generate the form later. By verifying the challenge string,
// we can make sure that the has the private key in their posession, and they haven't just sent someone else's public
// key.
	createX509(spkac, challenge) {
// Of course the SPKAC string sent by the browser won't meet the needs of OpenSSL's `skpac` utility, so we need to
// adjust it a bit.
		spkac = 'SPKAC=' + spkac.replace(/[\r\n]/g, '')
		const certP = new Promise((resolve, reject) => {
			const spkacProcess = exec('openssl spkac -verify', (error, stdout, stderr) => {
				if (error) reject(error)
				else {
// OpenSSL outputs the whole ASN.1 tree, so we need to extract the bit we're interested in. This command also verifies
// the signature: if it's invalid, it will return with an error code. It doesn't verify the *content* of the challenge
// though: as a [replay attack](https://en.wikipedia.org/wiki/Replay_attack), an attacker could have intercepted a
// previous, legitimate SPKAC message and sent it to us. By checking the challenge value, we can make sure it was
// generated to our request.
					const challenge_ = stdout.match(/Challenge String: (\d+)/)[1]
					if (challenge_ && parseInt(challenge_, 10) === challenge) resolve()
					else reject(new Error('SPKAC contains an invalid challenge string'))
				}
			})

			spkacProcess.stdin.write(spkac)
			spkacProcess.stdin.end()
// Once we verified the SPKAC, we can use it to generate an X.509 certificate using our server private key. We cannot
// `openssl x509` here, as it doesn't support SPKAC, only CSR. Instead, we use the more advanced `openssl ca` command.
// This command uses a config file, which contains the path to the server key and the certificate (among other things),
// an example can be found in the [git repository for this article](https://github.com/sevcsik/client-certificate-demo/releases/tag/chapter-2).
//
// Also note that unlike in the CSR scenario, we set the subject in this step. The SPKAC doesn't contain any data
// regarding the subject, even if it did, we couldn't trust it because it comes from the client.
//
// We need prefix the our command with `cat |`, because Node.js doesn't create a POSIX pipe for the standard input, so
// it cannot be opened via `/dev/stdin`. See this [Node.js issue](https://github.com/nodejs/node-v0.x-archive/issues/3530#issuecomment-6561239)
// for details.
		}).then(() => new Promise((resolve, reject) => {
			const ca = exec(`cat | openssl ca -batch -notext -spkac /dev/stdin -config ssl/openssl.cnf -subj /CN=${this.uid}`
				, (error, stdout, stderr) => {
					if (error) reject(error)
					else resolve(stdout)
				})

			ca.stdin.write(spkac)
			ca.stdin.end()
		}))
// Once we have the certificate, we get the fingerprint and save it to our instance, so we can use it for finding it
// later. We have to return the original promise though, as the output of this call should be the PEM itself, not the
// fingerprint.
		certP.then(this.getFingerprint).then(fingerprint => this.fingerprint = fingerprint)
		return certP
	}

// Server-side key-generation
// --------------------------
//
// For browsers without `<keygen>` support (which [has become far less ubiquitious recently](https://groups.google.com/a/chromium.org/forum/#!msg/blink-dev/z_qEpmzzKh8/BH-lkwdgBAA))
// we have to resort to generating the private key on the server. I won't get into much details here as I already wrote
// about it in my [previous post](https://sevdev.hu/ipns/sevdev.hu/posts/2017-07-22-authentication-using-https-client-certificates.html)
// What's interesting here is that we have to pipe the commands to avoid the use of temporary files, which can be
// less-than-obvious with OpenSSL's strange relationship to stdin.
	generatePkcs12() {
		return new Promise((resolve, reject) => {
			let key
			const keygen = exec('openssl genrsa 4096', (error, stdout, stderr) => key = stdout)
// We have add the `-batch` flag to disable interactive questions for the CSR and a confirmation creating the cert.
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
// To avoid an interactive password prompt, pass the `-password pass:` argument. It means that we give the password
// directly as an argument, which is an empty string. We might as well specify a password here (either a random one
// or prompting the user when requesting), because the browser asks for a password on import even if it's empty.
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
}

// Authentication
// ==============
//
// Our authentication flow will have three stages. In the first stage, the user is unauthenticated. This stage happens
// when the user doesn't provide a valid certificate, nor a valid session cookie.
//
// Our second phase (which I will refer to "half-authenticated") is where the user is logged in using their username
// and a password. In this phase, they cannot access the protected resources yet, but they can request a certificate.
//
// In the third stage, the user has a valid certificate and can access anything.

// For the sake of brevity, we'll use a dead simple in-memory object as our database. This is wrong on so many levels,
// like storing passwords in plain text, but this post isn't about password authentication, nor databases, so I keep
// it as simple as possible.
const db = [ { uid: 'Alice', password: 'password', certs: [], data: 'such sensitive data' }
           , { uid: 'Bob', password: 'letmein', certs: [], data: 'even more sensitive data' }
           ]

// For our protected routes, we need a parametised middleware. We can get the actual middleware with
// `requireAuthantication('half')` of `full`.
const requireAuthentication = level => (req, res, next) => {
// For convenience, if the user has a valid session, we look it up and add it to the request object (like Passport)
	const user = db.find(user => user.uid === req.session.uid)
	req.user = user
// If we need only half-authentication, and we have it already, we're good to go. We'll set the `authentication` field
// later in our authentication endpoints.
	if (level === 'half' && req.session.authentication === level) {
		next()
// If we need the client to be fully authenticated, we still need to check if the certificate has been revoked. If so,
// we revoke the authentication level and drop them to the login screen. We'll populate the `fingerprint` field later
// at our authentication endpoints. This will allow us to invalidate sessions as soon as the certificate is revoked.
	} else if (level === 'full' && req.session.authentication === level) {
		const cert = user.certs.find(cert => cert.fingerprint === req.session.fingerprint)
		if (cert && !cert.revoked) {
			next()
		} else {
			req.flash('error', 'Your certificate has been revoked, delete your certificate and log in again.')
			req.session.authentication = null
			res.redirect('/password-login')
		}
// If we need to elevate the authentication level, we just redirect the user to the certificate authentication endpoint.
	} else if (req.session.authentication === 'half' && level === 'full') {
		res.redirect('/verify-certificate')
	} else {
		res.redirect('/password-login')
	}
}

// Now we need an authentication endpoint for our second phase: nothing interesting here, just a simple (and bad!)
// password login flow.
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
// If the password matches, we can set the authentication level to 'half'. We just redirect to `/`, as that will be
// our only page - if we had multiple pages, we could use a `redirect_uri` parameter to send the user to the correct
// page.
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
		res.redirect('/create-certificate')
	}
})

app.get('/create-x509', requireAuthentication('half'), (req, res) => {
	const challenge = Math.floor(Math.random() * 100000000)
	req.session.challenge = challenge
	res.send(`<form method="POST">
	             <keygen name="pubkey" keytype="RSA" challenge="${challenge}">
	             <input type="submit" value="Create certificate">
	          </form>`)
})

app.post('/create-x509', requireAuthentication('half'), (req, res) => {
	const cert = new Cert(req.user.uid, req.headers['user-agent'])
	req.user.certs.push(cert)
	const x509 = cert.createX509(req.body.pubkey, req.session.challenge).then((x509) => {
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

app.get('/create-certificate', (req, res) => {
	res.send(`
		<form><keygen id="keygen"></form>
		<script>
			var keygen = document.getElementById('keygen')
			if (typeof HTMLKeygenElement !== undefined || keygen.getAttribute('_moz-type') === '-mozilla-keygen') {
				document.location.href = '/create-x509'
			} else {
				document.location.href = '/create-pkcs12'
			}
		</script>
	`)
})


app.get('/download-pkcs12/:fingerprint/certificate.p12', requireAuthentication('half'), (req, res) => {
	const cert = req.user.certs.find(cert => cert.fingerprint === req.params.fingerprint)
	if (cert) {
		if (cert.p12) {
			res.type('application/x-pkcs12')
			res.send(cert.p12)
		} else {
			res.send(`You have already used this key, please creaate a new one.
				      <a href="/create-certificate">Click here to create a new certificate</a>.`)
		}
	} else {
		res.send(`The download link is invalid.
		          <a href="/create-certificate">Click here to create a new certificate</a>.`)
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
// - [KEYGEN support does not belong in the parser](https://bugzilla.mozilla.org/show_bug.cgi?id=101019)
