package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/boyvinall/hydra-idp-form/providers/form"
	"github.com/janekolszak/idp/core"
	"github.com/janekolszak/idp/providers/cookie"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/net/context"
)

type HandlerConfig struct {
	IDP            *core.IDP
	Provider       core.Provider // interface, not pointer
	CookieProvider *cookie.CookieAuth
	ConsentForm    string
	RegisterForm   string
	StaticFiles    string
}

type IdpHandler struct {
	HandlerConfig

	consentTemplate  *template.Template
	registerTemplate *template.Template
	router           *httprouter.Router
}

type RegisterContext struct {
	Msg       string
	CancelURI string
}

func CreateHandler(config HandlerConfig) (*IdpHandler, error) {
	h := IdpHandler{HandlerConfig: config}

	var err error
	h.consentTemplate, err = template.New("consent").Parse(h.ConsentForm)
	if err != nil {
		return nil, err
	}

	if h.RegisterForm != "" {
		h.registerTemplate, err = template.New("register").Parse(h.RegisterForm)
		if err != nil {
			return nil, err
		}
	}

	return &h, nil
}

func (h *IdpHandler) LogRequest(r *http.Request, format string, a ...interface{}) {
	log.Printf(`%s (%s) %s "%s" "%s" "%s"`,
		r.RemoteAddr,
		r.Header.Get("X-Forwarded-For"),
		r.Method,
		r.URL.Path,
		fmt.Sprintf(format, a...),
		r.UserAgent())
}

func (h *IdpHandler) Attach(router *httprouter.Router) {
	router.GET("/", h.HandleChallengeGET)
	router.POST("/", h.HandleChallengePOST)
	router.GET("/cancel", h.HandleCancel)
	router.POST("/cancel", h.HandleCancel)
	router.GET("/consent", h.HandleConsentGET)
	router.POST("/consent", h.HandleConsentPOST)
	router.GET("/userinfo/:token", h.HandleUserinfoGET)
	if h.RegisterForm != "" {
		router.GET("/register", h.HandleRegisterGET)
	}
	router.POST("/register", h.HandleRegisterPOST) // can be posted from "register" form on "login" page
	if h.StaticFiles != "" {
		router.ServeFiles("/static/*filepath", http.Dir(h.StaticFiles))
	}
	router.GET("/verify", h.HandleVerifyGET)
}

func (h *IdpHandler) HandleCancel(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	challenge, err := h.IDP.GetChallenge(r)
	if err != nil {
		h.Provider.WriteError(w, r, err)
		return
	}
	// TODO: cleanup any cookies etc
	challenge.RefuseAccess(w, r)
	return
}

func (h *IdpHandler) HandleRegisterGET(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	query := url.Values{}
	query["challenge"] = []string{r.URL.Query().Get("challenge")}
	context := RegisterContext{
		Msg:       r.FormValue("msg"),
		CancelURI: fmt.Sprintf("/cancel?%s", query.Encode()),
	}

	err := h.registerTemplate.Execute(w, context)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *IdpHandler) HandleRegisterPOST(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	username, err := h.Provider.Register(r)
	if err != nil {
		query := url.Values{}
		query["challenge"] = []string{r.URL.Query().Get("challenge")}
		h.LogRequest(r, "Provider.Register(): %s", err.Error())

		switch err {

		case core.ErrorPasswordMismatch:
			query["msg"] = []string{"Passwords do not match"}

		case core.ErrorComplexityFailed:
			query["msg"] = []string{"Username/password does not meet required complexity"}

		case core.ErrorUserAlreadyExists:
			query["msg"] = []string{"user already exists"}

		default:
			// 	query["msg"] = []string{err.Error()}
		}
		http.Redirect(w, r, fmt.Sprintf("/?%s", query.Encode()), http.StatusFound)
		return
	}

	h.LogRequest(r, "Provider.Register(): OK")
	h.RedirectConsent(w, r, username, true)
}

func (h *IdpHandler) HandleChallengeGET(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	// for "form" provider GET, this just displays the form
	h.LogRequest(r, "HandleChallengeGET(): OK")
	h.Provider.WriteError(w, r, nil)
}

func (h *IdpHandler) HandleChallengePOST(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	saveCookie := true
	selector, userid, err := h.CookieProvider.Check(r)
	if err == nil {
		err = h.CookieProvider.UpdateCookie(w, r, selector, userid)
		if err != nil {
			h.LogRequest(r, "UpdateCookie(): %s", err.Error())
			return
		}
		h.LogRequest(r, "UpdateCookie(): OK")
		saveCookie = false
	} else {
		// Can't authenticate with "Remember Me" cookie,
		// so try with another provider:
		userid, err = h.Provider.Check(r)
		if err != nil {
			// for "form" provider GET, this just displays the form
			err2 := h.Provider.WriteError(w, r, err)
			if err2 != nil {
				h.LogRequest(r, "Provider.WriteError(): %s", err2.Error())
				return
			}
			h.LogRequest(r, "Provider.Check(): %s", err.Error())
			return
		}
		h.LogRequest(r, "Provider.Check(): OK")
	}
	h.RedirectConsent(w, r, userid, saveCookie)
}

// RedirectConsent may optionally skip the consent page if the clientID is trusted
func (h *IdpHandler) RedirectConsent(w http.ResponseWriter, r *http.Request,
	subject string, saveCookie bool) {

	challenge, err := h.IDP.NewChallenge(r, subject)
	if err != nil {
		h.LogRequest(r, "NewChallenge(): %s", err.Error())
		h.Provider.WriteError(w, r, err)
		return
	}

	// fmt.Printf("clientID %s\n", challenge.Client.GetID())
	trustedClient := true // TODO: detect based on client ID

	if trustedClient {

		err = challenge.GrantAccessToAll(w, r)
		if err != nil {
			// Server error
			h.LogRequest(r, "GrantAccessToAll(): %s", err.Error())
			h.Provider.WriteError(w, r, err)
			return
		}
		h.LogRequest(r, "GrantAccessToAll(): OK")
		return
	}

	if saveCookie {
		// Save the RememberMe cookie
		err := h.CookieProvider.SetCookie(w, r, subject)
		if err != nil {
			h.LogRequest(r, "error setting cookie: %s", err.Error())
		}
	}

	err = challenge.Save(w, r)
	if err != nil {
		h.LogRequest(r, "error saving challenge: %s", err.Error())
		h.Provider.WriteError(w, r, err)
		return
	}

	h.LogRequest(r, "OK, consent")
	http.Redirect(w, r, "/consent", http.StatusFound)
}

func (h *IdpHandler) HandleConsentGET(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	challenge, err := h.IDP.GetChallenge(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = h.consentTemplate.Execute(w, challenge)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *IdpHandler) HandleConsentPOST(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

	challenge, err := h.IDP.GetChallenge(r)
	if err != nil {
		h.Provider.WriteError(w, r, err)
		return
	}

	answer := r.FormValue("result")
	if answer != "ok" {
		// No challenge token
		// TODO: Handle negative answer
		challenge.RefuseAccess(w, r)
		return
	}

	err = challenge.GrantAccessToAll(w, r)
	if err != nil {
		// Server error
		h.Provider.WriteError(w, r, err)
		return
	}
}

func (h *IdpHandler) httpError(w http.ResponseWriter, errorMsg string, statusCode int) {
	type Error struct {
		msg string `json:"error"`
	}
	e := Error{msg: errorMsg}
	b, err := json.Marshal(e)
	var s string
	if err != nil {
		s = `{"error":"unknown error"}`
	} else {
		s = string(b)
	}
	http.Error(w, s, statusCode)
}

func (h *IdpHandler) HandleUserinfoGET(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	w.Header().Set("Content-Type", "application/json")

	token := ps.ByName("token")
	ctx := context.Background()
	wardenctx, err := h.IDP.WardenAuthorized(ctx, token, "openid")
	if err != nil {
		h.LogRequest(r, "fail: %s", err.Error())
		h.httpError(w, "token denied or not found", http.StatusForbidden)
		return
	}

	h.LogRequest(r, r.URL.RawQuery)

	id := wardenctx.Subject
	p := h.Provider.(*form.FormAuth)
	user, err := p.Config.UserStore.GetWithID(id)

	w.Header().Set("X-Subject", id)

	// type Context struct {
	// 	Subject       string    `json:"sub"`
	// 	GrantedScopes []string  `json:"scopes"`
	// 	Issuer        string    `json:"iss"`
	// 	Audience      string    `json:"aud"`
	// 	IssuedAt      time.Time `json:"iat"`
	// 	ExpiresAt     time.Time `json:"exp"`
	// }

	if err != nil {
		h.LogRequest(r, "fail: %s", err.Error())
		errorMsg := err.Error()
		status := http.StatusInternalServerError
		switch err {
		case core.ErrorNoSuchUser:
			status = http.StatusNotFound

		default:
		}
		h.httpError(w, errorMsg, status)
		return
	}

	type userinfo struct {
		ID       string `json:"id"`
		Email    string `json:"email"`
		Name     string `json:"name"`
		Username string `json:"username"`
	}
	u := userinfo{
		ID:       id,
		Email:    user.GetEmail(),
		Username: user.GetUsername(),
		Name:     strings.TrimSpace(fmt.Sprintf("%s %s", user.GetFirstName(), user.GetLastName())),
	}
	b, err := json.Marshal(u)
	if err != nil {
		// This should never happen
		h.LogRequest(r, "fail: %s", err.Error())
		h.httpError(w, "serialisation error", http.StatusInternalServerError)
		return
	}
	h.LogRequest(r, "OK")
	fmt.Fprint(w, string(b))
}

func (h *IdpHandler) HandleVerifyGET(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	userid, err := h.Provider.Verify(r)
	if err != nil {
		h.LogRequest(r, err.Error())
		h.Provider.WriteError(w, r, err)
		return
	}

	h.LogRequest(r, "OK")
	h.Provider.WriteVerify(w, r, userid)
}
