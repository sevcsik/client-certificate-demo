// -----------------------------------------------------
// title: Authentication using HTTPS client certificates
// -----------------------------------------------------
//
// We hear a lot about how passwords are insecure, and should not be used alone for authentication. They are hard to
// remember, so users are tempted to come up with weak passwords, and reuse them across multiple websites. Even if the
// password is strong, it's still just a short string the users *know*.
//
// There are numerous ways to mitigate this, such as [HMAC or][1] [time-based one-time passwords][2] or more recently
// [universal 2nd-factor][3] hardware tokens. They all based on something the user *has*, rather than something they
// *know*. What they *have* is a secret key, which they can use to generate a password or sign messages.
//
// What seems to be forgotten in the consumer world is that every browser has had a feature built-in since TLS was
// introduced, called [mutual authentication][4], which allows the user to present a certificate
// as well as the server. This means the user can authenticate with something they *have* and -- if the certificate
// is protected by a passphrase -- something they *know*.
//
// In this post, we implement a simple Node.js example which uses client certificates to authenticate the user.
//
// <!-- TEASER -->
//
// We only one need external dependency, `express`, otherwise, we just depend on the standard Node.js HTTPS server.
// We also need `fs` to read the certificates/keys to configure HTTPS.
//

const express = require('express')
const fs = require('fs')
const https = require('https')

// Setting up the private key and the certificate
// ==============================================
//
// First of all, we need to generate our keys and certificates. We use the `openssl` command-line tool. On
// Linux, it's likely already installed -- if not, install the `openssl` package of your distribution. On Windows it's
// a bit trickier, see [this tutorial][5];
//
// Like with every regular HTTPS server, we need to generate a server certificate. For the sake of brevity, we
// use a self-signed certificate here -- in real life, you probably want to use a well-known certificate authority,
// such as [Let's Encrypt][6].
//
// To generate a self-signed certificate (in our case, without encryption):
// ```bash
// $ openssl req -x509 -newkey rsa:4096 -keyout server_key.pem -out server_cert.pem -nodes -days 365 -subj "/CN=localhost/O=Client\ Certificate\ Demo"
// ```
//
// This is actually a three-step process combined into one command:
//
// - Create a new 4096bit RSA key and save it to `server_key.pem`, *without* DES encryption (`-newkey`, `-keyout`
//   and `-nodes`)
// - Create a Certificate Signing Request for a given subject, valid for 365 days (`-days`, `-subj`)
// - Sign the CSR using the server key, and save it to `server_cert.pem` as an X.509 certificate (`-x509`, `-out`)
//
// We could have also done this with tree commands, `openssl genrsa`, `openssl req` and `openssl x509`. We used the PEM
// format (the default setting), which is a base64-encoded text file with a
// `----- BEGIN/END CERTIFICATE/PRIVATE KEY -----` header and footer. Another option would be the DER format,
// which uses binary encoding. There is a bit of a confusion what the file extension should refer to: it's also common
// to use `.key` or `.crt`, referring to the contents of the file rather than the encoding (in which case they can
// contain both DER- and PEM-encoded data).
//
// Configuring the Node.js HTTP server
// ===================================
//
// Let's add our server key and certificate to the `options object`, which we pass to the HTTPS server later:
const opts = { key: fs.readFileSync('server_key.pem')
             , cert: fs.readFileSync('server_cert.pem')
// Next, we instruct the HTTPS server to request a client certificate from the user
             , requestCert: true
// Then we tell it to accept requests with no valid certificate. We need this to handle invalid connections as well
// (for example to display an error message), otherwise, they would just get a cryptic HTTPS error message from the
// browser (`ERR_BAD_SSL_CLIENT_AUTH_CERT` to be precise)

             , rejectUnauthorized: false
// Finally, we supply a list of CA certificates that we consider valid. For now, we sign client certificates with
// our own server key, so it will be the same as our server certificate.

             , ca: [ fs.readFileSync('server_cert.pem') ]
             }

// Then we create our app. We use express only for routeing here -- we could use the [`passport` middleware][7] as
// well, with a [strategy for client certificates][8], but for now, we keep things simple.

const app = express()

// We add our "landing page" first. This is unprotected, so everyone will see it whether they present a client cert
// or not.

app.get('/', (req, res) => {
	res.send('<a href="authenticate">Log in using client certificate</a>')
})

// Then we add our protected endpoint: it just displays information about the user and the validity of their
// certificate. We can get the certificate information from the HTTPS connection handle:

app.get('/authenticate', (req, res) => {
	const cert = req.connection.getPeerCertificate()

// The `req.client.authorized` flag will be true if the certificate is valid and was issued by a CA we white-listed
// earlier in `opts.ca`. We display the name of our user (CN = Common Name) and the name of the issuer, which is
// `localhost`.

	if (req.client.authorized) {
		res.send(`Hello ${cert.subject.CN}, your certificate was issued by ${cert.issuer.CN}!`)
// They can still provide a certificate which is not accepted by us. Unfortunately, the `cert` object will be an empty
// object instead of `null` if there is no certificate at all, so we have to check for a known field rather than
// truthiness.

	} else if (cert.subject) {
		res.status(403)
		   .send(`Sorry ${cert.subject.CN}, certificates from ${cert.issuer.CN} are not welcome here.`)
// And last, they can come to us with no certificate at all:
	} else {
		res.status(401)
		   .send(`Sorry, but you need to provide a client certificate to continue.`)
	}
})

// Let's create our HTTPS server and we're ready to go.
https.createServer(opts, app).listen(9999)

// Then we can start our server with `npm i && node server.js`.

// Setting up client certificates
// ==============================
//
// If we try to "log in" to our site now, we get a `401` response, because we don't have any client
// certificates yet. To test our setup, we create two certificates for our two users, Alice and Bob. Alice is nice
// as she has a valid certificate issued by us, while Bob is nasty and tries to log in using a self-signed certificate.
//
// To create a key and a Certificate Signing Request for Alice and Bob we can use the following command:
//
// ```bash
// $ openssl req -newkey rsa:4096 -keyout alice_key.pem -out alice_csr.pem -nodes -days 365 -subj "/CN=Alice"
// $ openssl req -newkey rsa:4096 -keyout bob_key.pem -out bob_csr.pem -nodes -days 365 -subj "/CN=Bob"
// ```
//
// We sign Alice's CSR with our key and save it as a certificate. Here, we act as a Certificate Authority, so we
// supply our certificate and key via the `-CA` parameters:
// ```bash
// $ openssl x509 -req -in alice_csr.pem -CA server_cert.pem -CAkey server_key.pem -out alice_cert.pem -set_serial 01 -days 365
// ```
//
// Bob doesn't believe in authority, so he just signs his certificate on his own:
// ```bash
// $ openssl x509 -req -in bob_csr.pem -signkey bob_key.pem -out bob_cert.pem -days 365
// ```
//
// Trying to get in
// ================
//
// To use these certificates in our browser, we need to bundle them in PKCS#12 format. That will contain both the
// private key and the certificate, thus the browser can use it for encryption. For Alice, we add the `-clcerts` option,
// which excludes the CA certificate from the bundle. Since we issued the certificate, we already have the
// certificate: we don't need to include it in Alice's certificate as well. You can also password-protect the certificate.
//
// ```bash
// $ openssl pkcs12 -export -clcerts -in alice_cert.pem -inkey alice_key.pem -out alice.p12
// $ openssl pkcs12 -export -in bob_cert.pem -inkey bob_key.pem -out bob.p12
// ```
//
// We can import these private keys to the browser. In Firefox, go to *Preferences -> Advanced -> View Certificates
// -> Import*, and choose both files.
//
// If you open [https://localhost:9999](https://localhost:9999) in the browser now, a dialog will come up to choose a
// certificate. Note that only Alice's certificate is in the list: that's because the browser already knows that only
// certs issued by us will be accepted (because we advertise it using the `opts.ca` list). If you continue, you'll see
// our success message with the details of Alice.
//
// This is only a browser limitation, you can still try to get in with Bob's cert using cURL:
// ```bash
// $ curl --insecure --cert bob.p12 --cert-type p12 https://localhost:9999/authenticate
// ```
// And see that Bob's not welcome here!
//
// Of course this solution isn't practical in real life: we don't want to genereate keys for our users via the command
// line and have them installing them into their browsers manually. In the next article, we'll see how we can generate
// new client certificates dynamically and install them seamlessly to the users' browser.
//
// To try this server, there clone [this post's github repo][9], where you can also find the keys and certificates.
//
// Sources
// =======
// - [SSL Client Authentication in Node.js](http://nategood.com/nodejs-ssl-client-cert-auth-api-rest)
// - [Q12149 - HOWTO: DER vs. CRT vs. CER vs. PEM Certificates and How To Convert Them](http://info.ssl.com/article.aspx?id=12149)
// - [Mini tutorial for configuring client-side SSL certificates](https://gist.github.com/mtigas/952344)
// - [client-certificate-auth](https://github.com/tgies/client-certificate-auth/blob/master/lib/clientCertificateAuth.js)
// - [diegows's answer to "How to create a self-signed certificate with openssl?"](https://stackoverflow.com/questions/10175812/how-to-create-a-self-signed-certificate-with-openssl#10176685)
//
// [1]: https://en.wikipedia.org/wiki/HMAC-based_One-time_Password_Algorithm
// [2]: https://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm
// [3]: https://en.wikipedia.org/wiki/Universal_2nd_Factor
// [4]: https://en.wikipedia.org/wiki/Mutual_authentication
// [5]: https://www.tbs-certificates.co.uk/FAQ/en/openssl-windows.html
// [6]: https://letsencrypt.org/
// [7]: http://passportjs.org/
// [8]: https://github.com/ripjar/passport-client-cert
// [9]: https://github.com/sevcsik/client-certificate-demo/tree/chapter-1

