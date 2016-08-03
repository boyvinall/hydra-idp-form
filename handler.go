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

	if h.RegisterForm != "" {
		h.registerTemplate, err = template.New("register").Parse(h.RegisterForm)
		if err != nil {
			return nil, err
		}
	}

	return &h, nil
}

func (h *IdpHandler) Attach(router *httprouter.Router) {
	router.GET("/", h.HandleChallengeGET)
	router.POST("/", h.HandleChallengePOST)
	router.GET("/cancel", h.HandleCancel)
	router.POST("/cancel", h.HandleCancel)
	router.GET("/consent", h.HandleConsentGET)
	router.POST("/consent", h.HandleConsentPOST)
	if h.RegisterForm != "" {
		router.GET("/register", h.HandleRegisterGET)
	}
	router.POST("/register", h.HandleRegisterPOST) // can be posted from "register" form on "login" page
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
	username, err := h.Provider.Register(r)
	if err != nil {
		query := url.Values{}
		query["challenge"] = []string{r.URL.Query().Get("challenge")}
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

	h.RedirectConsent(w, r, username, true)
}

func (h *IdpHandler) HandleChallengeGET(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	// for "form" provider GET, this just displays the form
	h.Provider.WriteError(w, r, nil)
}

func (h *IdpHandler) HandleChallengePOST(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	saveCookie := true
	selector, user, err := h.CookieProvider.Check(r)
	if err == nil {
		err = h.CookieProvider.UpdateCookie(w, r, selector, user)
		if err != nil {
			fmt.Println("cookie error")
			return
		}
		saveCookie = false
	} else {
		// Can't authenticate with "Remember Me" cookie,
		// so try with another provider:
		user, err = h.Provider.Check(r)
		if err != nil {
			// for "form" provider GET, this just displays the form
			err = h.Provider.WriteError(w, r, err)
			if err != nil {
				fmt.Println(err.Error())
			}
			return
		}
	}
	h.RedirectConsent(w, r, user, saveCookie)
}

// RedirectConsent may optionally skip the consent page if the clientID is trusted
func (h *IdpHandler) RedirectConsent(w http.ResponseWriter, r *http.Request,
	user string, saveCookie bool) {

	challenge, err := h.IDP.NewChallenge(r, user)
	if err != nil {
		h.Provider.WriteError(w, r, err)
		return
	}

	// fmt.Printf("clientID %s\n", challenge.Client.GetID())
	trustedClient := true // TODO: detect based on client ID

	if trustedClient {

		err = challenge.GrantAccessToAll(w, r)
		if err != nil {
			// Server error
			h.Provider.WriteError(w, r, err)
			return
		}
		return
	}

	if saveCookie {
		// Save the RememberMe cookie
		err := h.CookieProvider.SetCookie(w, r, user)
		if err != nil {
			fmt.Println(err.Error())
		}
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
