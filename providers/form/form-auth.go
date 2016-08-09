package form

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"

	"github.com/janekolszak/idp/core"
	"github.com/janekolszak/idp/userdb"
)

type LoginFormContext struct {
	Msg         string
	SubmitURI   string
	RegisterURI string
}

type Config struct {
	LoginForm          string
	LoginEmailField    string
	LoginPasswordField string

	RegisterEmailField           string
	RegisterPasswordField        string
	RegisterPasswordConfirmField string

	Email     Complexity
	Password  Complexity
	UserStore userdb.UserStore
}

type FormAuth struct {
	Config
}

func NewFormAuth(c Config) (*FormAuth, error) {
	if c.LoginEmailField == "" ||
		c.LoginPasswordField == "" ||
		c.LoginEmailField == c.LoginPasswordField {
		return nil, core.ErrorInvalidConfig
	}

	if len(c.Email.Patterns) == 0 {
		c.Email.Patterns = []string{".*"}
	}

	if len(c.Password.Patterns) == 0 {
		c.Password.Patterns = []string{".*"}
	}

	auth := FormAuth{Config: c}
	return &auth, nil
}

func (f *FormAuth) Check(r *http.Request) (id string, err error) {
	email := r.FormValue(f.LoginEmailField)
	if !f.Config.Email.Validate(email) {
		err = core.ErrorBadRequest
		return
	}

	password := r.FormValue(f.LoginPasswordField)
	if !f.Config.Password.Validate(password) {
		err = core.ErrorBadRequest
		return
	}

	id, err = f.UserStore.CheckWithEmail(email, password)
	if err != nil {
		id = ""
		err = core.ErrorAuthenticationFailure
	}

	return
}

func (f *FormAuth) Register(r *http.Request) (id string, err error) {
	email := r.FormValue(f.RegisterEmailField)
	password := r.FormValue(f.RegisterPasswordField)
	confirm := r.FormValue(f.RegisterPasswordConfirmField)

	if password != confirm {
		err = core.ErrorPasswordMismatch
	}

	if !f.Config.Password.Validate(password) {
		err = core.ErrorComplexityFailed
	}

	if !f.Config.Email.Validate(email) {
		err = core.ErrorComplexityFailed
	}

	if err != nil {
		return
	}

	// log.Printf("attempt to insert email %s\n", email)
	user := userdb.User{
		Email:    email,
		Username: email,
	}

	id, err = f.UserStore.Insert(&user, password)
	if err != nil {
		id = ""
		return
	}

	// _, err = f.UserVerifier.Push(id, data.Username, data.Email)
	// log.Printf("inserted email %s = ID %s\n", email, id)
	return
}

func (f *FormAuth) WriteRegister(w http.ResponseWriter, r *http.Request) error {
	return core.ErrorNotImplemented
}

func (f *FormAuth) Verify(r *http.Request) (userid string, err error) {
	return "", core.ErrorNotImplemented
}

func (f *FormAuth) WriteVerify(w http.ResponseWriter, r *http.Request, userid string) error {
	return core.ErrorNotImplemented
}

func (f *FormAuth) WriteError(w http.ResponseWriter, r *http.Request, err error) error {
	query := url.Values{}
	query["challenge"] = []string{r.URL.Query().Get("challenge")}
	context := LoginFormContext{
		SubmitURI:   r.URL.RequestURI(),
		RegisterURI: fmt.Sprintf("/register?%s", query.Encode()),
	}

	if r.Method == "POST" && err != nil {
		switch err {
		case core.ErrorAuthenticationFailure:
			context.Msg = "Authentication failed"

		default:
			context.Msg = "An error occurred"
		}
	} else {
		context.Msg = r.URL.Query().Get("msg")
	}
	t := template.Must(template.New("tmpl").Parse(f.LoginForm))
	return t.Execute(w, context)
}

func (f *FormAuth) Write(w http.ResponseWriter, r *http.Request) error {
	return nil
}
