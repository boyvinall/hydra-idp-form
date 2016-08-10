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

	Email    Complexity
	Password Complexity

	UserStore userdb.UserStore

	VerifyForm   string
	UserVerifier userdb.UserVerifier
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

	_, err = f.UserVerifier.Push(id, user.Username, user.Email)
	return
}

func (f *FormAuth) WriteRegister(w http.ResponseWriter, r *http.Request) error {
	return core.ErrorNotImplemented
}

func (f *FormAuth) Verify(r *http.Request) (userid string, err error) {
	code := r.URL.Query().Get("code")
	userid, err = f.UserVerifier.Verify(code)
	if err != nil {
		return "", err
	}

	err = f.UserStore.SetIsVerifiedWithID(userid)
	if err != nil {
		return "", err
	}

	return userid, nil
}

func (f *FormAuth) WriteVerify(w http.ResponseWriter, r *http.Request, userid string) error {
	user, err := f.UserStore.GetWithID(userid)
	if err != nil {
		return err
	}

	data := map[string]string{
		"Username":  user.Username,
		"FirstName": user.FirstName,
		"LastName":  user.LastName,
		"Email":     user.Email,
	}

	w.Header().Set("Cache-Control", "no-cache")
	t := template.Must(template.New("tmpl").Parse(f.VerifyForm))
	return t.Execute(w, data)
}

func (f *FormAuth) WriteError(w http.ResponseWriter, r *http.Request, err error) error {
	msg := r.URL.Query().Get("msg")
	if r.Method == "POST" && err != nil {
		switch err {
		case core.ErrorAuthenticationFailure:
			msg = "Authentication failed"

		default:
			msg = "An error occurred"
		}
	}
	return f.WriteLoginPage(w, r, msg)
}

func (f *FormAuth) WriteLoginPage(w http.ResponseWriter, r *http.Request, msg string) error {
	query := url.Values{}
	query["challenge"] = []string{r.URL.Query().Get("challenge")}
	context := LoginFormContext{
		SubmitURI:   fmt.Sprintf("/?%s", query.Encode()),
		RegisterURI: fmt.Sprintf("/register?%s", query.Encode()),
		Msg:         msg,
	}

	w.Header().Set("Cache-Control", "no-cache")
	t := template.Must(template.New("tmpl").Parse(f.LoginForm))
	return t.Execute(w, context)
}

func (f *FormAuth) Write(w http.ResponseWriter, r *http.Request) error {
	return nil
}
