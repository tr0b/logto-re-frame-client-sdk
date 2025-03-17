[![Clojars Project](https://img.shields.io/clojars/v/com.github.tr0b/logto-re-frame-client-sdk.svg)](https://clojars.org/com.github.tr0b/logto-re-frame-client-sdk)

## WARNING ⚠️⚠️⚠️⚠️⚠️

**THIS IS A WORK IN PROGRESS (WIP) LIBRARY FOR MY OWN, PERSONAL USE. IT IS CURRENTLY UNTESTED AND LITERALLY 95% OF THE CODE WAS GENERATED VIA LLMs (Claude Sonnet 3.7), AS I WAS IN A RUSH TO HAVE A WORKING, AUTH FRAMEWORK INTEGRATED DIRECTLY WITH CLOJURE(SCRIPT). THIS LIBRARY MIGHT BE SUBJECTED TO RE-WRITES (OR POTENTIAL DEPRECATION) IN THE NEAR-FUTURE. USE AT YOUR OWN RISK. I'M NOT RESPONSIBLE FOR ANY HARM, MISUSE OR DAMAGE CAUSED BY THE USAGE OF THIS LIBRARY.**

# Logto Client SDK for re-frame

This is a ClojureScript implementation of the Logto Client SDK for use with re-frame applications. It provides a clean, idiomatic way to integrate Logto authentication into your re-frame-based ClojureScript applications.

## Features

- Complete OpenID Connect authentication flow
- Token management (ID tokens, access tokens, refresh tokens)
- User information retrieval
- Resource-specific access token management
- Integration with re-frame's event and subscription system

## Installation

Add the following dependency to your project.clj or deps.edn:

```
com.github.tr0b/logto-re-frame-client-sdk {:mvn/version "0.0.8"}

```
```clojure
[logto-client "0.0.1"]
```

## Usage

### Initialize the SDK

First, initialize the SDK with your Logto configuration:

```clojure
(ns your-app.events
  (:require
   [re-frame.core :as rf]
   [logto-client.core :as logto]))

(rf/reg-event-fx
 ::initialize-app
 (fn [_ _]
   {:fx [[:dispatch [::logto/initialize-logto
                     {:endpoint "https://your-logto-endpoint.com"
                      :app-id "your-app-id"
                      :scopes ["openid" "profile" "email"]}]]
         [:dispatch [::logto/fetch-oidc-config]]]}))
```

### Sign In

To start the sign-in process:

```clojure
(rf/dispatch [::logto/sign-in "https://your-app.com/callback"])
```

### Handle Callback

When the user is redirected back to your application:

```clojure
(rf/dispatch [::logto/handle-sign-in-callback js/window.location.href])
```

### Check Authentication Status

Subscribe to the authentication status:

```clojure
(let [authenticated? @(rf/subscribe [::logto/is-authenticated])]
  (if authenticated?
    [:div "You are logged in!"]
    [:div "Please log in"]))
```

### Get User Information

Retrieve user information:

```clojure
(let [user-info @(rf/subscribe [::logto/user-info])]
  [:div
   [:h1 "Welcome, " (:name user-info)]
   [:p "Email: " (:email user-info)]])
```

### Get Access Tokens

Get access tokens for protected resources:

```clojure
;; Request an access token if needed
(rf/dispatch [::logto/get-access-token "api-resource" ["read" "write"]])

;; Use the access token
(let [token @(rf/subscribe [::logto/access-token "api-resource"])]
  ;; Use token in API calls
  )
```

### Sign Out

Sign the user out:

```clojure
(rf/dispatch [::logto/sign-out])
```

## Advanced Usage

### Custom Storage

By default, the SDK uses cookies for temporary storage. You can implement custom storage by overriding the cookie events and effects.

### Token Verification

The SDK includes basic token verification. In production, you should implement more robust verification.

## Example Application

See the `logto-example` directory for a complete example application that demonstrates all features of the SDK.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
