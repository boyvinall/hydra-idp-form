[![Build Status](https://travis-ci.org/boyvinall/hydra-idp-form.svg?branch=master)](https://travis-ci.org/boyvinall/hydra-idp-form)

This is an oauth2 identity provider (IDP).

Based primarily on [github.com/janekolszak/idp](https://github.com/janekolszak/idp), this
is an application that solves the specific use-cases that I have.

## To do

(some of this functionality will be added to the form provider in
[github.com/janekolszak/idp](https://github.com/janekolszak/idp))
- sign-up
- add some sort of db persistence
- login with google/github

further out:
- ensure this can be run in a redundant/HA configuration, including
    - eliminate single-host data stores
    - ensure clean operation with SSL-offloading
- possibly integrate client for [letsencrypt](https://letsencrypt.org/)

## See also

- [github.com/ory-am/hydra](https://github.com/ory-am/hydra)


