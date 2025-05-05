(ns logto-client.core
  (:require
   [re-frame.core :as re-frame]
   [clojure.string :as str]
   [shadow.cljs.modern :refer (js-await)]
   [lambdaisland.uri :refer [map->query-string query-map]]
   ["dayjs" :as dayjs]
   [goog.crypt :as crypt]
   [goog.crypt.base64 :as base64]))

;; -- View actions for sign-in/sign-out buttons

(def redirect-uri "http://localhost:3000/callback")

;; (defn handle-sign-in []
;;   #(re-frame/dispatch [::events/sign-in redirect-uri]))
;; 
;; (defn handle-sign-out []
;;  ; #(re-frame/dispatch [::events/sign-out redirect-uri])
;;   (js/console.error "SIGN OUT NOT IMPLEMENTED YET. WIP"))

;; --- Config (re-frame DB default values) ---
(defonce default-config
  {:logto-base-endpoint "http://localhost:3001/"
   :logto-oidc-endpoint "http://localhost:3001/oidc/.well-known/openid-configuration"
   :auth-token-loading? false
   :authenticated? false
   :oidc-config-loading? false
   :auth-config {:app-id "rn6fs3o60ww1spaht9c4r"
                 :scopes ["openid" "profile" "email"]
                 :resources []
                 :oidc-config nil}
   :auth-tokens nil
   :user-info nil})

(defonce cookie-expire-time
  1800 ;; 30 minutes
  )

;; --- Utility functions ---

(def date-time-zone-format "YYYY-MM-DD HH:mm:ss ZZ")

(defn add-minutes [minutes ^js dayjs-object]
  "Adds minutes to now datetime (requires dayjs). Returns UNIX timestamp string."
  (.unix (.add dayjs-object minutes "minute") date-time-zone-format))

(def oidc-discovery-path
  "/oidc/.well-known/openid-configuration")

(defn base-64-uri-safe-string [uint8array]
  (let [base-64-string (str/join "" (map js/String.fromCharCode uint8array))]
    (-> base-64-string
        (js/btoa)
        (str/replace #"=" "")
        (str/replace #"[+\/]" (fn [matched]
                                (if (= matched "+")
                                  "-"
                                  "_"))))))

(defn random-string
  "Generates a random string for code-verifier challenge"
  ([] (random-string 64))
  ([length]
   (let [array (js/crypto.getRandomValues (js/Uint8Array. length))]
     (base-64-uri-safe-string (array-seq array)))))

(defn generate-pkce-code-challenge
  "Generates a code challenge from a code verifier."
  [code-verifier]
  (let [encoded-code-verifier (.encode (js/TextEncoder.) code-verifier)]
    (js-await [result (js/crypto.subtle.digest "SHA-256" encoded-code-verifier)]
              (base-64-uri-safe-string (js/Uint8Array. result))
              (catch error
                     (js/console.error "Error generating PKCE code challenge:" error)
                nil))))

;; New declarative signIn function and supporting functions
(defn create-pkce []
  (let [code-verifier (random-string)]
    (js-await [code-challenge (generate-pkce-code-challenge code-verifier)]
              {:code-verifier code-verifier
               :code-challenge code-challenge})))

(defn create-auth-params [{:keys [app-id redirect-uri pkce state scopes resources]}]
  (let [reserved-scopes ["openid" "offline_access" "profile"]
        all-scopes (concat reserved-scopes scopes)
        base-params {:client_id app-id
                     :redirect_uri redirect-uri
                     :code_challenge (:code-challenge pkce)
                     :code_challenge_method "S256"
                     :state state
                     :response_type "code"
                     :prompt "consent"
                     :scope (str/join " " all-scopes)}]
    (if (seq resources)
      (assoc base-params :resource resources)
      base-params)))

(defn store-sign-in-session! [data]
  (.setItem js/sessionStorage "sign-in-session" (js/JSON.stringify (clj->js data))))

(defn save-tokens! [data]
  (let [refresh-token (:refresh_token data)
        id-token (:id_token data)
        access-token (:access_token data)
        expires_in (:expires_in data)]
    (.setItem js/sessionStorage "refresh-token" refresh-token)
    (.setItem js/sessionStorage "id-token" id-token)
    (.setItem js/sessionStorage "" (js/JSON.stringify (clj->js {:token access-token
                                                                :expires_at (add-minutes expires_in (dayjs))})))))

(defn get-sign-in-session []
  (let [session-data (.getItem js/sessionStorage "sign-in-session")]
    (js->clj (js/JSON.parse session-data) :keywordize-keys true)))

(defn verify-and-parse-code-from-callback-uri
  "Verifies the callback URI and extracts the authorization code.
   Returns {:error <error msg> :code nil} if it fails to verify/parse 
   Returns {:error nil :code string} if it successfully verifies/parses"
  [callback-uri redirect-uri state]
  (let [parameters (query-map callback-uri)]

    ;; Check if callback URI starts with redirect URI
    (when-not (str/starts-with? callback-uri redirect-uri)
      {:error "redirect_uri_mismatched"})

    ;; Check for error messages
    (let [{error :error
           error-description :error_description
           callback-state :state
           code :code} parameters]

      (when (or error error-description)
        {:error (str error ":" error-description)})

      (when-not (= callback-state state)
        {:error "state_mismatch"})

      (when-not nil
        {:error "authorization_code_not_found"})
      {:error nil :code code})))

(defn redirect! [url]
  (set! (.-location js/window) url))

(defn sign-in
  "Declarative implementation of signIn function"
  [{:keys [app-id resources scopes oidc-config]} redirect-uri]
  (let [state (random-string)]
    (js-await [pkce (create-pkce)]
              (let [auth-params (create-auth-params {:app-id app-id
                                                     :redirect-uri redirect-uri
                                                     :pkce pkce
                                                     :state state
                                                     :scopes scopes
                                                     :resources resources})
                    query-string (map->query-string auth-params)
                    external-auth-url (str (:authorization_endpoint oidc-config) "?" query-string)]

                ;; Store session for verification later
                (store-sign-in-session! {:redirect-uri redirect-uri
                                         :state state
                                         :code-verifier (:code-verifier pkce)})

                ;; Navigate to authorization URL
                (redirect! external-auth-url)))))

(defn base64-url-decode
  "Decode base64url encoded string"
  [s]
  (let [s (-> s
              (str/replace #"-" "+")
              (str/replace #"_" "/")
              ;; Add padding if needed
              (#(if (zero? (mod (count %) 4))
                  %
                  (str % (apply str (repeat (- 4 (mod (count %) 4)) "="))))))]
    (base64/decodeString s)))

(defn decode-jwt-payload
  "Decode JWT payload using Closure libraries"
  [token]
  (let [[_ payload-b64] (str/split token #"\.")]
    (try
      (let [decoded-payload (base64-url-decode payload-b64)
            payload-str (crypt/byteArrayToString
                         (crypt/stringToByteArray decoded-payload))]
        (js->clj (js/JSON.parse payload-str) :keywordize-keys true))
      (catch :default e
        (js/console.error "Error decoding JWT payload:" e)
        nil))))

(defn token-expired?
  "Check if JWT is expired"
  [decoded-token]
  (let [current-time (/ (.now js/Date) 1000)]
    (> current-time (:exp decoded-token))))

(defn token-claims
  "Extract specific claims from JWT"
  [decoded-token]
  (select-keys decoded-token [:sub :iss :aud :exp :iat]))

(defn token-aud-matches?
  [decoded-token app-id]
  (= (:aud decoded-token) app-id))

(defn token-iss-matches?
  [decoded-token issuer]
  (= (:iss decoded-token) issuer))

;; --- Events ---
;; LOGTO SDK

(defn http-oidc-config [db callback-uri success-event]
  {:db (assoc db :oidc-config-loading? true)
   :http-xhrio {:method          :get
                :uri             (:logto-oidc-endpoint db)
                :timeout         5000
                :response-format (ajax/json-response-format {:keywords? true})
                :on-success      [success-event callback-uri]
                :on-failure      [::handle-failure-fetch-oidc-config]}})

(re-frame/reg-event-fx
 ::sign-in
 (fn [{:keys [db]} [_ callback-uri]]
   {:fx [[:dispatch [::fetch-oidc-config callback-uri ::sign-in-fx]]]}))

(re-frame/reg-event-fx
 ::fetch-oidc-config
 (fn [{:keys [db]} [_ callback-uri success-event]]
   (http-oidc-config db callback-uri success-event)))

(re-frame/reg-event-db
 ::handle-failure-fetch-oidc-config
 (fn [db [_ _]]
   (-> db
       (assoc :error "Error fetching OIDC config")
       (assoc :oidc-config-loading? false))))

(re-frame/reg-event-fx
 ::sign-in-fx
 (fn [{:keys [db]} [_ redirect-uri response]]
   (sign-in (conj (:auth-config db) {:oidc-config response}) redirect-uri)))

;; SIGN IN CALLBACK

(re-frame/reg-event-fx
 ::handle-sign-in-callback
 (fn [{:keys [db]} [_ callback-uri]]
   {:fx [[:dispatch [::fetch-oidc-config callback-uri ::handle-sign-in-callback-fx]]]}))

(re-frame/reg-event-fx
 ::handle-sign-in-callback-fx
 (fn [{:keys [db]} [_ callback-uri response]]
   (let [sign-in-session (get-sign-in-session)]
     (if (nil? sign-in-session)
       {:fx [[:dispatch [::handle-failure-sign-in-callback "sign_in_session.not_found"]]]}
       (let [{:keys [redirect-uri state code-verifier]} sign-in-session
             {code :code verify-parse-error :error} (verify-and-parse-code-from-callback-uri callback-uri redirect-uri state)
             {token-endpoint :token_endpoint jwks-uri :jwks_uri} response]
         (if-not (nil? verify-parse-error)
           {:fx [[:dispatch [::handle-failure-sign-in-callback verify-parse-error]]]}
           {:fx [[:dispatch [::fetch-auth-token {:code code
                                                 :client-id (get-in db [:auth-config :app-id])
                                                 :token-endpoint token-endpoint
                                                 :redirect-uri redirect-uri
                                                 :code-verifier code-verifier
                                                 :oidc-config response
                                                 :auth-config (:auth-config db)}]]]}))))))
(re-frame/reg-event-db
 ::sign-in-callback-success
 (fn [db [_ response]]
   (save-tokens! response)
   (-> db
       (assoc :error nil)
       (assoc :oidc-config-loading? false)
       (assoc :auth-token-loading? false)
       (assoc :authenticated? true)
       (assoc :auth-tokens response))))

(re-frame/reg-event-db
 ::handle-failure-sign-in-callback
 (fn [db [_ error-message]]
   (-> db
       (assoc :error (str "Authentication error: " error-message))
       (assoc :oidc-config-loading? false)
       (assoc :auth-token-loading? false)
       (assoc :authenticated? false))))

(re-frame/reg-event-fx
 ::verify-id-token
 (fn [{:keys [db]} [_ response]]
   (let [decoded-jwt (decode-jwt-payload (:id_token response))]
     (when (nil? decoded-jwt)
       {:fx [[:dispatch [::handle-failure-sign-in-callback "Error decoding JWT on verify-id-token event: Invalid JWT"]]]})
     (when (token-expired? decoded-jwt)
       {:fx [[:dispatch [::handle-failure-sign-in-callback "Error decoding JWT on verify-id-token event: Token expired"]]]})
     {:fx [[:dispatch [::sign-in-callback-success response]]]})))

(re-frame/reg-event-fx
 ::fetch-auth-token
 (fn [{:keys [db]} [_ payload]]
   {:db   (assoc db :auth-token-loading? true)
    :http-xhrio {:method          :post
                 :uri             (:token-endpoint payload)
                 :body          (js/URLSearchParams. (clj->js {:client_id (:client-id payload)
                                                               :code (:code payload)
                                                               :code_verifier (:code-verifier payload)
                                                               :redirect_uri (:redirect-uri payload)
                                                               :grant_type "authorization_code"}))
                 :headers         {"Content-Type" "application/x-www-form-urlencoded"}
                 :timeout         5000
                 :response-format (ajax/json-response-format {:keywords? true})
                 :on-success      [::verify-id-token]
                 :on-failure      [::handle-failure-sign-in-callback]}}))

;; Subscriptions
(re-frame/reg-sub
 ::authenticated?
 (fn [db]
   (:authenticated? db)))

(re-frame/reg-sub
 ::auth-token-loading?
 (fn [db]
   (:auth-token-loading? db)))

(re-frame/reg-sub
 ::error
 (fn [db]
   (:error db)))

(re-frame/reg-sub
 ::logto-base-endpoint
 (fn [db]
   (:logto-base-endpoint db)))

(re-frame/reg-sub
 ::auth-config
 (fn [db]
   (:auth-config db)))

;; --- Cookie fx --- (TODO: might be invalid. or can be used as replacement for the save-tokens! function above)
;; (rf/reg-fx
;;  :cookie/set
;;  (fn [{:keys [name value expires]}]
;;    (.set Cookies name value #js {:expires expires})))
;; 
;; (rf/reg-fx
;;  :cookie/remove
;;  (fn [name]
;;    (.remove Cookies name)))

(js/console.log "logto-client.core loaded")
