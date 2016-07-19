package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	"github.com/janekolszak/idp/core"
	"github.com/janekolszak/idp/providers/cookie"
	"github.com/janekolszak/idp/providers/form"
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

var (
	hydraURL     = flag.String("hydra", "https://localhost:4444", "Hydra's URL")
	htpasswdPath = flag.String("htpasswd", "/etc/idp/htpasswd", "Path to credentials in htpasswd format")
	cookieDBPath = flag.String("cookie-db", "/etc/idp/remember.db3", "Path to a database with remember me cookies")
	clientID     = flag.String("client-id", "", "used to connect to hydra")
	clientSecret = flag.String("client-secret", "", "used to connect to hydra")
	staticFiles  = flag.String("static", "", "directory to serve as /static (for CSS/JS/images etc)")
	loginFile    = flag.String("login", "", "template to present for the login page")
	consentFile  = flag.String("consent", "", "template to present for the consent page")
)

func main() {
	flag.Parse()
	fmt.Println("Identity Provider started!")

	if *loginFile != "" {
		buf, err := ioutil.ReadFile(*loginFile)
		if err != nil {
			panic(err)
		}
		loginform = string(buf)
	}

	if *consentFile != "" {
		buf, err := ioutil.ReadFile(*consentFile)
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

	err = userdb.LoadHtpasswd(*htpasswdPath)
	if err != nil {
		panic(err)
	}

	provider, err := form.NewFormAuth(form.Config{
		LoginForm:                    loginform,
		LoginUsernameField:           "username",
		LoginPasswordField:           "password",
		RegisterUsernameField:        "username",
		RegisterPasswordField:        "password",
		RegisterPasswordConfirmField: "confirm",

		// Store for
		UserStore: userdb,

		// Validation options:
		Username: form.Complexity{
			MinLength: 1,
			MaxLength: 100,
			Patterns:  []string{".*"},
		},
		Password: form.Complexity{
			MinLength: 1,
			MaxLength: 100,
			Patterns:  []string{".*"},
		},
	})
	if err != nil {
		panic(err)
	}

	u, err := url.Parse(*cookieDBPath)
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
		ClusterURL:            *hydraURL,
		ClientID:              *clientID,
		ClientSecret:          *clientSecret,
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
		StaticFiles:    *staticFiles,
	})

	router := httprouter.New()
	handler.Attach(router)
	http.ListenAndServe(":3000", router)

	idp.Close()
}
