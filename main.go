package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/boyvinall/hydra-idp-form/providers/form"

	"github.com/asaskevich/govalidator"
	"github.com/boj/rethinkstore"
	"github.com/janekolszak/idp/core"
	"github.com/janekolszak/idp/providers/cookie"
	"github.com/urfave/cli"
	// "github.com/janekolszak/idp/providers/form"
	"github.com/janekolszak/idp/userdb/rethinkdb/store"
	"github.com/julienschmidt/httprouter"
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
)

type Config struct {
	hydraURL      string
	dbURL         string
	clientID      string
	clientSecret  string
	staticFiles   string
	loginFile     string
	consentFile   string
	emailRegex    string
	passwordRegex string
}

func run(cfg *Config) {
	log.Println("Identity Provider started!")

	u, err := url.Parse(cfg.dbURL)
	if err != nil {
		panic(err)
	}
	if u.Scheme != "rethinkdb" {
		panic(fmt.Sprintln("only rethinkdb supported at present:", cfg.dbURL))
	}
	dbhost := u.Host
	dbname := strings.TrimLeft(u.Path, "/")
	log.Println("dbhost:", dbhost)
	log.Println("dbname:", dbname)

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

	session, err := r.Connect(r.ConnectOpts{
		Address:  dbhost,
		Database: dbname,
	})
	if err != nil {
		panic(err)
	}

	// Setup the providers
	userdb, err := store.NewStore(session)
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

		// Store for
		UserStore: userdb,

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

	dbCookieStore, err := cookie.NewRethinkDBStore(dbhost, dbname)
	if err != nil {
		panic(err)
	}
	defer dbCookieStore.Close()

	cookieProvider := &cookie.CookieAuth{
		Store:  dbCookieStore,
		MaxAge: time.Minute * 1,
	}

	challengeCookieStore, err := rethinkstore.NewRethinkStore(dbhost, dbname, "challenges", 5, 5, []byte("something-very-secret"))
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
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "hydra",
			Value:  "https://localhost:4444",
			Usage:  "Hydra's URL",
			EnvVar: "HYDRA_URL",
		},
		cli.StringFlag{
			Name:   "db",
			Value:  "rethinkdb://localhost:28015/idp",
			Usage:  "Where are the cookies/challenges/users stored? (table names are hardcoded within this database)",
			EnvVar: "DB_URL",
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
	app.Action = func(cfg *cli.Context) {
		run(&Config{
			hydraURL:      cfg.String("hydra"),
			dbURL:         cfg.String("db"),
			clientID:      cfg.String("client-id"),
			clientSecret:  cfg.String("client-secret"),
			staticFiles:   cfg.String("static"),
			loginFile:     cfg.String("login"),
			consentFile:   cfg.String("consent"),
			emailRegex:    cfg.String("email-regex"),
			passwordRegex: cfg.String("password-regex"),
		})
	}

	app.Run(os.Args)
}
