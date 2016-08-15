package main

import (
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/boyvinall/hydra-idp-form/providers/form"

	"github.com/asaskevich/govalidator"
	"github.com/boj/rethinkstore"
	"github.com/janekolszak/idp/core"
	"github.com/janekolszak/idp/helpers"
	"github.com/janekolszak/idp/providers/cookie"
	"github.com/janekolszak/idp/userdb/rethinkdb/store"
	"github.com/janekolszak/idp/userdb/rethinkdb/verifier"
	"github.com/julienschmidt/httprouter"
	"github.com/urfave/cli"
	r "gopkg.in/dancannon/gorethink.v2"
)

var (
	consent = `<html>
<head>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
<p>User:        {{.User}} </p>
<p>Client Name: {{.Client.Name}} </p>
<p>Scopes:      {{range .Scopes}} {{.}} {{end}} </p>
<p>Do you agree to grant access to those scopes? </p>
<p><form method="post">
    <input type="submit" name="result" value="ok">
    <input type="submit" name="result" value="cancel">
</form></p>
</body>
</html>
`

	loginform = `<html>
<head>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
<form method="post" action="{{.SubmitURI}}">
	<h2>Login</h2>
    <p>username <input type="text" name="username"></p>
    <p>password <input type="password" name="password" autocomplete="off"></p>
    <p><input type="submit" name="result" value="login"></p>
</form>
<form method="post" action="{{.RegisterURI}}">
	<h2>Register</h2>
    <p>username <input type="text" name="username"></p>
    <p>password <input type="password" name="password" autocomplete="off"></p>
    <p>confirm password <input type="password" name="confirm"  autocomplete="off"></p>
    <p><input type="submit"></p>
</form>
<hr>
{{.Msg}}
</body>
</html>`

	verifypage = `<html>
<head>
</head>
<body>
<p>Welcome {{.Email}}!</p>
<p>You have successfully verified your email address.
Please click <a href="{{.LoginURL}}">here</a> to manage your account.</p>
</body>
</html>`

	verifytext = `Hi there!,

Please visit {{.URL}} to verify your email address.

Thanks
--
This email was sent to {{.Email}}`

	verifyhtml = `<p>Hi there!</p>
<p></p>
<p>Please click <a href={{.URL}}>here</a> to verify your email address.</p>
<p></p>
<p>Thanks</p>
<hr>
<small>This email was sent to {{.Email}}`
)

type Config struct {
	hydraURL        string
	dbURL           string
	clientID        string
	clientSecret    string
	staticFiles     string
	loginFile       string
	consentFile     string
	emailRegex      string
	passwordRegex   string
	challengeSecret string

	smtpUrl        string
	emailDomain    string
	emailFrom      string
	emailSubject   string
	consentUrl     string
	verifyTextFile string
	verifyHtmlFile string
	verifyPageFile string
}

func run(cfg *Config) {
	log.Println("Identity Provider started!")

	// ===================================================
	//   HTML/email Templates

	if cfg.loginFile != "" {
		buf, err := ioutil.ReadFile(cfg.loginFile)
		if err != nil {
			panic(err)
		}
		loginform = string(buf)
	}

	if cfg.consentFile != "" {
		buf, err := ioutil.ReadFile(cfg.consentFile)
		if err != nil {
			panic(err)
		}
		consent = string(buf)
	}

	if cfg.verifyTextFile != "" {
		buf, err := ioutil.ReadFile(cfg.verifyTextFile)
		if err != nil {
			panic(err)
		}
		verifytext = string(buf)
	}

	if cfg.verifyHtmlFile != "" {
		buf, err := ioutil.ReadFile(cfg.verifyHtmlFile)
		if err != nil {
			panic(err)
		}
		verifyhtml = string(buf)
	}

	if cfg.verifyPageFile != "" {
		buf, err := ioutil.ReadFile(cfg.verifyPageFile)
		if err != nil {
			panic(err)
		}
		verifypage = string(buf)
	}

	// ===================================================
	//   Connect to database

	u, err := url.Parse(cfg.dbURL)
	if err != nil {
		panic(err)
	}
	if u.Scheme != "rethinkdb" {
		fmt.Println("Please specify rethinkdb:// for the database URL")
		os.Exit(1)
	}
	dbhost := u.Host
	dbname := strings.TrimLeft(u.Path, "/")

	session, err := r.Connect(r.ConnectOpts{
		Address:  dbhost,
		Database: dbname,
	})
	if err != nil {
		panic(err)
	}

	// ===================================================
	//   Create main authentication provider

	userdb, err := store.NewStore(session)
	if err != nil {
		panic(err)
	}

	ver, err := verifier.NewVerifier(session)
	if err != nil {
		panic(err)
	}

	if cfg.emailRegex == "" {
		cfg.emailRegex = govalidator.Email
	}

	provider, err := form.NewFormAuth(form.Config{
		LoginForm:                    loginform,
		LoginEmailField:              "email",
		LoginPasswordField:           "password",
		RegisterEmailField:           "email",
		RegisterPasswordField:        "password",
		RegisterPasswordConfirmField: "confirm",
		UserStore:                    userdb,
		UserVerifier:                 ver,
		VerifyForm:                   verifypage,

		// Validation options:
		Email: form.Complexity{
			MinLength: 1,
			MaxLength: 100,
			Patterns:  []string{cfg.emailRegex},
		},
		Password: form.Complexity{
			MinLength: 1,
			MaxLength: 100,
			Patterns:  []string{cfg.passwordRegex},
		},
	})
	if err != nil {
		panic(err)
	}

	// ===================================================
	//   Create cookie authentication provider

	dbCookieStore, err := cookie.NewRethinkDBStore(dbhost, dbname)
	if err != nil {
		panic(err)
	}
	defer dbCookieStore.Close()

	cookieProvider := &cookie.CookieAuth{
		Store:  dbCookieStore,
		MaxAge: time.Minute * 1,
	}

	// ===================================================
	//   Create IDP

	challengeCookieStore, err := rethinkstore.NewRethinkStore(dbhost, dbname,
		"challenges",
		5, 5,
		[]byte(cfg.challengeSecret))
	if err != nil {
		panic(err)
	}
	defer challengeCookieStore.Close()
	challengeCookieStore.MaxAge(60 * 5) // 5 min

	idp := core.NewIDP(&core.IDPConfig{
		ClusterURL:            cfg.hydraURL,
		ClientID:              cfg.clientID,
		ClientSecret:          cfg.clientSecret,
		KeyCacheExpiration:    10 * time.Minute,
		ClientCacheExpiration: 10 * time.Minute,
		CacheCleanupInterval:  30 * time.Second,
		ChallengeStore:        challengeCookieStore,
	})
	defer idp.Close()

	// Connect with Hydra
	err = idp.Connect()
	if err != nil {
		panic(err)
	}

	// ===================================================
	//   Email verification

	emailOpts := helpers.EmailerOpts{
		From:         cfg.emailFrom,
		TextTemplate: template.Must(template.New("tmpl").Parse(verifytext)),
		HtmlTemplate: template.Must(template.New("tmpl").Parse(verifyhtml)),
		Domain:       cfg.emailDomain,
		Subject:      cfg.emailSubject,
	}
	{
		u, err := url.Parse(cfg.smtpUrl)
		if err != nil {
			panic(err)
		}

		// set some info directly from the parsed URL
		if u.User != nil {
			emailOpts.User = u.User.Username()
			emailOpts.Password, _ = u.User.Password()
		}

		// host/port need a little more glue..

		host := strings.SplitN(u.Host, ":", 2)
		var port int
		emailOpts.Host = host[0]
		if len(host) > 1 {
			port, err = strconv.Atoi(host[1])
			if err != nil {
				fmt.Println("Unable to parse SMTP port from", u.Host)
				os.Exit(1)
			}
		}
		switch u.Scheme {
		case "smtp":
			if port == 0 {
				port = 25
			}
			emailOpts.Secure = false

		case "smtps":
			if port == 0 {
				port = 465
			}
			emailOpts.Secure = true

		default:
			fmt.Println("Please specify smtp:// or smtps:// for the smtp-url")
			os.Exit(1)
		}

		emailOpts.Port = port
	}

	verifierWorker, err := verifier.NewWorker(verifier.WorkerOpts{
		Session:         session,
		EndpointAddress: cfg.consentUrl + "verify",
		RequestMaxAge:   time.Minute * 1,
		CleanupInterval: time.Minute * 60,
		EmailerOpts:     emailOpts,
	})
	if err != nil {
		panic(err)
	}
	err = verifierWorker.Start()
	if err != nil {
		panic(err)
	}
	defer verifierWorker.Stop()

	// ===================================================
	//   HTTP handlers

	handler, err := CreateHandler(HandlerConfig{
		IDP:            idp,
		Provider:       provider,
		CookieProvider: cookieProvider,
		ConsentForm:    consent,
		StaticFiles:    cfg.staticFiles,
	})

	router := httprouter.New()
	handler.Attach(router)
	http.ListenAndServe(":3000", router)

}

func main() {
	app := cli.NewApp()
	app.Name = "hydra-idp-form"
	app.Usage = "Form-based IDP for Hydra"
	app.Version = "0.0.1"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "hydra",
			Value:  "https://localhost:4444",
			Usage:  "Hydra's URL",
			EnvVar: "HYDRA_URL",
		},
		cli.StringFlag{
			Name:   "client-id",
			Value:  "",
			Usage:  "used to connect to hydra",
			EnvVar: "HYDRA_CLIENT_ID",
		},
		cli.StringFlag{
			Name:   "client-secret",
			Value:  "",
			Usage:  "used to connect to hydra",
			EnvVar: "HYDRA_CLIENT_SECRET",
		},
		cli.StringFlag{
			Name:   "db",
			Value:  "rethinkdb://localhost:28015/idp",
			Usage:  "Where are the cookies/challenges/users stored? (table names are hardcoded within this database)",
			EnvVar: "DB_URL",
		},
		cli.StringFlag{
			Name:   "static",
			Value:  "",
			Usage:  "directory to serve as /static (for CSS/JS/images etc)",
			EnvVar: "STATIC_DIR",
		},
		cli.StringFlag{
			Name:   "login-template",
			Value:  "",
			Usage:  "file path for template to present as the login page",
			EnvVar: "LOGIN_TEMPLATE_FILE",
		},
		cli.StringFlag{
			Name:   "consent-template",
			Value:  "",
			Usage:  "file path for template to present as the consent page",
			EnvVar: "CONSENT_TEMPLATE_FILE",
		},
		cli.StringFlag{
			Name:   "verify-page-template",
			Value:  "",
			Usage:  "file path for template to present as the verify page",
			EnvVar: "VERIFY_PAGE_TEMPLATE_FILE",
		},
		cli.StringFlag{
			Name:   "verify-text-template",
			Value:  "",
			Usage:  "template for plain-text version of email-address verification email",
			EnvVar: "VERIFY_TEXT_TEMPLATE_FILE",
		},
		cli.StringFlag{
			Name:   "verify-html-template",
			Value:  "",
			Usage:  "template for HTML version of email-address verification email",
			EnvVar: "VERIFY_HTML_TEMPLATE_FILE",
		},
		cli.StringFlag{
			Name:   "email-regex",
			Value:  "",
			Usage:  "regex to validate email address (defaults to govalidator.Email)",
			EnvVar: "EMAIL_REGEX",
		},
		cli.StringFlag{
			Name:   "password-regex",
			Value:  `(.){8,}`,
			Usage:  "regex to validate password",
			EnvVar: "PASSWORD_REGEX",
		},
		cli.StringFlag{
			Name:   "challenge-secret",
			Value:  "something-very-secret",
			Usage:  "used to encrypt challenges in the database",
			EnvVar: "CHALLENGE_SECRET",
		},
		cli.StringFlag{
			Name:   "consent-url",
			Value:  "http://localhost:3000/",
			Usage:  "used when sending verification emails etc .. should be publicly-accessible and should have trailing slash",
			EnvVar: "CONSENT_URL",
		},
		cli.StringFlag{
			Name:   "email-domain",
			Value:  "localhost:3000",
			Usage:  "used for the email-verification Message-Id",
			EnvVar: "EMAIL_DOMAIN",
		},
		cli.StringFlag{
			Name:   "email-from",
			Value:  "noreply@localhost.local",
			Usage:  "used for the email-verification email",
			EnvVar: "EMAIL_FROM",
		},
		cli.StringFlag{
			Name:   "email-subject",
			Value:  "Please verify your account",
			Usage:  "used for the email-verification email",
			EnvVar: "EMAIL_SUBJECT",
		},
		cli.StringFlag{
			Name:   "smtp-url",
			Value:  "smtp://127.0.0.1/",
			Usage:  "SMTP connection details .. supports smtp// or smtps://, user:password@ and port specifier",
			EnvVar: "SMTP_URL",
		},
		cli.StringFlag{
			Name:   "pprof-bind",
			Usage:  "[ip]:port to bind for http.DefaultServeMux, used to expose performance profiling info. The default (empty) means don't expose this.",
			Value:  "",
			EnvVar: "PPROF_BIND",
		},
	}
	app.Action = func(c *cli.Context) {
		pprofBind := c.String("pprof-bind")
		if pprofBind != "" {
			go func() {
				// see https://github.com/uber/go-torch
				log.Println(http.ListenAndServe(pprofBind, nil))
			}()
		}
		run(&Config{
			hydraURL:        c.String("hydra"),
			dbURL:           c.String("db"),
			clientID:        c.String("client-id"),
			clientSecret:    c.String("client-secret"),
			staticFiles:     c.String("static"),
			loginFile:       c.String("login-template"),
			consentFile:     c.String("consent-template"),
			emailRegex:      c.String("email-regex"),
			passwordRegex:   c.String("password-regex"),
			challengeSecret: c.String("challenge-secret"),
			consentUrl:      c.String("consent-url"),
			verifyTextFile:  c.String("verify-text-template"),
			verifyHtmlFile:  c.String("verify-html-template"),
			verifyPageFile:  c.String("verify-page-template"),
			emailDomain:     c.String("email-domain"),
			emailFrom:       c.String("email-from"),
			emailSubject:    c.String("email-subject"),
			smtpUrl:         c.String("smtp-url"),
		})
	}

	app.Run(os.Args)
}
