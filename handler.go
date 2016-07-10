package main

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"

	"github.com/janekolszak/idp/core"
	"github.com/janekolszak/idp/providers/cookie"
	"github.com/julienschmidt/httprouter"
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

	h.registerTemplate, err = template.New("register").Parse(h.RegisterForm)
	if err != nil {
		return nil, err
	}

	return &h, nil
}

func (h *IdpHandler) Attach(router *httprouter.Router) {
	router.GET("/", h.HandleChallenge)
	router.POST("/", h.HandleChallenge)
	router.GET("/cancel", h.HandleCancel)
	router.POST("/cancel", h.HandleCancel)
	router.GET("/consent", h.HandleConsentGET)
	router.POST("/consent", h.HandleConsentPOST)
	router.GET("/register", h.HandleRegisterGET)
	router.POST("/register", h.HandleRegisterPOST)
	if h.StaticFiles != "" {
		router.ServeFiles("/static/*filepath", http.Dir(h.StaticFiles))
	}
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
	query := url.Values{}
	query["challenge"] = []string{r.URL.Query().Get("challenge")}

	password := r.FormValue("password")
	confirm := r.FormValue("confirm")
	if password != confirm {
		query["msg"] = []string{"Passwords do not match"}
		http.Redirect(w, r, fmt.Sprintf("/register?%s", query.Encode()), http.StatusFound)
		return
	}
	username := r.FormValue("username")
	// TODO: does the user already exist?
	// TODO: store the user
	h.RedirectConsent(w, r, username, true)
}

func (h *IdpHandler) HandleChallenge(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	saveCookie := true
	selector, user, err := h.CookieProvider.Check(r)
	if err == nil {
		err = h.CookieProvider.UpdateCookie(w, r, selector, user)
		if err != nil {
			return
		}
		saveCookie = false
	} else {
		// Can't authenticate with "Remember Me" cookie,
		// so try with another provider:
		user, err = h.Provider.Check(r)
		if err != nil {
			// for "form" provider GET, this just displays the form
			h.Provider.WriteError(w, r, err)
			return
		}

	}
	h.RedirectConsent(w, r, user, saveCookie)
}

func (h *IdpHandler) RedirectConsent(w http.ResponseWriter, r *http.Request,
	user string, saveCookie bool) {

	if saveCookie {
		// Save the RememberMe cookie
		err := h.CookieProvider.SetCookie(w, r, user)
		if err != nil {
			fmt.Println(err.Error())
		}
	}

	challenge, err := h.IDP.NewChallenge(r, user)
	if err != nil {
		h.Provider.WriteError(w, r, err)
		return
	}

	err = challenge.Save(w, r)
	if err != nil {
		h.Provider.WriteError(w, r, err)
		return
	}

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
