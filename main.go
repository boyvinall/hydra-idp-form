package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/boyvinall/hydra-idp-form/providers/form"

	"github.com/asaskevich/govalidator"
	"github.com/codegangsta/cli"
	"github.com/gorilla/sessions"
	"github.com/janekolszak/idp/core"
	"github.com/janekolszak/idp/providers/cookie"
	// "github.com/janekolszak/idp/providers/form"
	"github.com/janekolszak/idp/userdb/memory"
	"github.com/julienschmidt/httprouter"
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
)

type Config struct {
	hydraURL      string
	htpasswdPath  string
	cookieDBPath  string
	clientID      string
	clientSecret  string
	staticFiles   string
	loginFile     string
	consentFile   string
	emailRegex    string
	passwordRegex string
}

func run(c *Config) {
	fmt.Println("Identity Provider started!")

	if c.loginFile != "" {
		buf, err := ioutil.ReadFile(c.loginFile)
		if err != nil {
			panic(err)
		}
		loginform = string(buf)
	}

	if c.consentFile != "" {
		buf, err := ioutil.ReadFile(c.consentFile)
		if err != nil {
			panic(err)
		}
		consent = string(buf)
	}

	// Setup the providers
	userdb, err := memory.NewMemStore()
	if err != nil {
		panic(err)
	}

	if c.htpasswdPath != "" {
		err = userdb.LoadHtpasswd(c.htpasswdPath)
		if err != nil {
			panic(err)
		}
	}

	if c.emailRegex == "" {
		c.emailRegex = govalidator.Email
	}

	provider, err := form.NewFormAuth(form.Config{
		LoginForm:                    loginform,
		LoginUsernameField:           "email",
		LoginPasswordField:           "password",
		RegisterUsernameField:        "email",
		RegisterPasswordField:        "password",
		RegisterPasswordConfirmField: "confirm",

		// Store for
		UserStore: userdb,

		// Validation options:
		Username: form.Complexity{
			MinLength: 1,
			MaxLength: 100,
			Patterns:  []string{c.emailRegex},
		},
		Password: form.Complexity{
			MinLength: 1,
			MaxLength: 100,
			Patterns:  []string{c.passwordRegex},
		},
	})
	if err != nil {
		panic(err)
	}

	u, err := url.Parse(c.cookieDBPath)
	if err != nil {
		panic(err)
	}
	if u.Scheme != "rethinkdb" {
		panic("cookiedb must be rethinkdb")
	}
	dbCookieStore, err := cookie.NewRethinkDBStore(u.Host, strings.TrimLeft(u.Path, "/"))
	if err != nil {
		panic(err)
	}
	defer dbCookieStore.Close()

	cookieProvider := &cookie.CookieAuth{
		Store:  dbCookieStore,
		MaxAge: time.Minute * 1,
	}

	idp := core.NewIDP(&core.IDPConfig{
		ClusterURL:            c.hydraURL,
		ClientID:              c.clientID,
		ClientSecret:          c.clientSecret,
		KeyCacheExpiration:    10 * time.Minute,
		ClientCacheExpiration: 10 * time.Minute,
		CacheCleanupInterval:  30 * time.Second,

		// TODO: [IMPORTANT] Don't use CookieStore here
		ChallengeStore: sessions.NewCookieStore([]byte("something-very-secret")),
	})

	// Connect with Hydra
	err = idp.Connect()
	if err != nil {
		panic(err)
	}

	handler, err := CreateHandler(HandlerConfig{
		IDP:            idp,
		Provider:       provider,
		CookieProvider: cookieProvider,
		ConsentForm:    consent,
		StaticFiles:    c.staticFiles,
	})

	router := httprouter.New()
	handler.Attach(router)
	http.ListenAndServe(":3000", router)

	idp.Close()

}

func main() {
	app := cli.NewApp()
	app.Name = "hydra-idp-form"
	app.Usage = "Form-based IDP for Hydra"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "hydra",
			Value:  "https://localhost:4444",
			Usage:  "Hydra's URL",
			EnvVar: "HYDRA_URL",
		},
		cli.StringFlag{
			Name:   "htpasswd",
			Value:  "",
			Usage:  "Path to credentials in htpasswd format",
			EnvVar: "HTPASSWD_FILE",
		},
		cli.StringFlag{
			Name:   "cookie-db",
			Value:  "rethinkdb://localhost:28015/idp_cookies",
			Usage:  "Where are the cookies stored?",
			EnvVar: "COOKIEDB_URL",
		},
		cli.StringFlag{
			Name:   "client-id",
			Value:  "",
			Usage:  "used to connect to hydra",
			EnvVar: "CLIENT_ID",
		},
		cli.StringFlag{
			Name:   "client-secret",
			Value:  "",
			Usage:  "used to connect to hydra",
			EnvVar: "CLIENT_SECRET",
		},
		cli.StringFlag{
			Name:   "static",
			Value:  "",
			Usage:  "directory to serve as /static (for CSS/JS/images etc)",
			EnvVar: "STATIC_DIR",
		},
		cli.StringFlag{
			Name:   "login",
			Value:  "",
			Usage:  "template to present for the login page",
			EnvVar: "LOGIN_TEMPLATE_FILE",
		},
		cli.StringFlag{
			Name:   "consent",
			Value:  "",
			Usage:  "template to present for the consent page",
			EnvVar: "CONSENT_TEMPLATE_FILE",
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
	}
	app.Action = func(c *cli.Context) {
		run(&Config{
			hydraURL:      c.String("hydra"),
			htpasswdPath:  c.String("htpasswd"),
			cookieDBPath:  c.String("cookie-db"),
			clientID:      c.String("client-id"),
			clientSecret:  c.String("client-secret"),
			staticFiles:   c.String("static"),
			loginFile:     c.String("login"),
			consentFile:   c.String("consent"),
			emailRegex:    c.String("email-regex"),
			passwordRegex: c.String("password-regex"),
		})
	}

	app.Run(os.Args)
}
