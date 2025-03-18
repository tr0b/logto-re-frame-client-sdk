(ns logto-client.core
  (:require
   [clojure.string :as str]
   [re-frame.core :as rf]
   [day8.re-frame.http-fx]
   [ajax.core :as ajax]
   [goog.crypt.base64 :as b64]
   ["js-cookie" :as Cookies]))

;; --- DB structure ---
;; {:logto {:config {...}
;;          :tokens {:id-token "..."
;;                   :refresh-token "..."
;;                   :access-tokens {"resource" {:token "..." :expires-at timestamp}}}
;;          :user-info {...}
;;          :oidc-config {...}}}

;; --- Config ---
(defonce default-config
  {:endpoint nil
   :app-id nil
   :scopes ["openid" "profile" "email"]})

(defonce cookie-expire-time
  1800 ;; 30 minutes
  )

;; --- Utility functions ---
(defn random-string [length]
  (let [chars "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        chars-length (count chars)]
    (apply str (repeatedly length #(nth chars (rand-int chars-length))))))

(defn sha256 [message]
  (let [hash (js/crypto.subtle.digest "SHA-256" (js/TextEncoder. "utf-8") .encode message)]
    ;; Convert to ArrayBuffer and then to Base64 URL format
    ;; This is a simplified version - in a real implementation you'd use a Promise
    (-> hash
        (.then (fn [buffer]
                 (let [bytes (js/Uint8Array. buffer)
                       base64 (b64/encodeByteArray bytes)]
                   (-> base64
                       (str/replace #"\+/=" "-_")
                       (str/replace #"=" ""))))))))

(defn code-challenge-from-verifier [verifier]
  (sha256 verifier))

(defn query-string [params]
  (str/join "&" (map (fn [[k v]] (str (name k) "=" (js/encodeURIComponent v))) params)))

(defn parse-query-string [query-string]
  (let [query (if (str/starts-with? query-string "?")
                (subs query-string 1)
                query-string)]
    (into {} (for [pair (str/split query #"&")]
               (let [[k v] (str/split pair #"=")]
                 [k (js/decodeURIComponent v)])))))

;; --- Events ---
(rf/reg-event-db
 ::initialize-logto
 (fn [db [_ config]]
   (let [merged-config (merge default-config config)]
     (assoc-in db [:logto :config] merged-config))))

(rf/reg-event-fx
 ::fetch-oidc-config
 (fn [{:keys [db]} _]
   (let [endpoint (get-in db [:logto :config :endpoint])]
     {:http-xhrio {:method :get
                   :uri (str endpoint "/.well-known/openid-configuration")
                   :response-format (ajax/json-response-format {:keywords? true})
                   :on-success [::fetch-oidc-config-success]
                   :on-failure [::request-failed]}})))

(rf/reg-event-db
 ::fetch-oidc-config-success
 (fn [db [_ response]]
   (assoc-in db [:logto :oidc-config] response)))

(rf/reg-event-fx
 ::fetch-jwks
 (fn [{:keys [db]} _]
   (let [jwks-uri (get-in db [:logto :oidc-config :jwks_uri])]
     {:http-xhrio {:method :get
                   :uri jwks-uri
                   :response-format (ajax/json-response-format {:keywords? true})
                   :on-success [::fetch-jwks-success]
                   :on-failure [::request-failed]}})))

(rf/reg-event-db
 ::fetch-jwks-success
 (fn [db [_ response]]
   (assoc-in db [:logto :jwks] response)))

(rf/reg-event-fx
 ::sign-in
 (fn [{:keys [db]} [_ redirect-uri]]
   (let [{:keys [endpoint app-id scopes]} (get-in db [:logto :config])
         authorization-endpoint (get-in db [:logto :oidc-config :authorization_endpoint])
         code-verifier (random-string 64)
         code-challenge (code-challenge-from-verifier code-verifier)
         state (random-string 16)
         params {:response_type "code"
                 :client_id app-id
                 :redirect_uri redirect-uri
                 :scope (str/join " " scopes)
                 :state state
                 :code_challenge code-challenge
                 :code_challenge_method "S256"
                 :prompt "consent"}
         auth-url (str authorization-endpoint "?" (query-string params))]
     {:db (-> db
              (assoc-in [:logto :sign-in-session :code-verifier] code-verifier)
              (assoc-in [:logto :sign-in-session :state] state))
      :fx [[:dispatch [::save-sign-in-session]]
           [:redirect auth-url]]})))

(rf/reg-fx
 :redirect
 (fn [url]
   (set! (.-location js/window) url)))

(rf/reg-event-fx
 ::save-sign-in-session
 (fn [{:keys [db]} _]
   (let [session (get-in db [:logto :sign-in-session])]
     {:cookie/set {:name "logto_sign_in_session"
                   :value (js/JSON.stringify (clj->js session))
                   :expires cookie-expire-time}}))) ; 30 minutes

(rf/reg-event-fx
 ::handle-sign-in-callback
 (fn [{:keys [db]} [_ callback-uri]]
   (let [uri (js/URL. callback-uri)
         query-params (parse-query-string (.-search uri))
         code (get query-params "code")
         state (get query-params "state")
         session-str (.get Cookies "logto_sign_in_session")
         session (js->clj (js/JSON.parse session-str) :keywordize-keys true)]
     (if (and code (= state (:state session)))
       {:db (assoc-in db [:logto :sign-in-session] session)
        :fx [[:dispatch [::exchange-code code (:code-verifier session) (.-origin uri)]]]}
       {:fx [[:dispatch [::sign-in-error "Invalid state parameter"]]]}))))

(rf/reg-event-fx
 ::exchange-code
 (fn [{:keys [db]} [_ code code-verifier redirect-uri]]
   (let [{:keys [app-id]} (get-in db [:logto :config])
         token-endpoint (get-in db [:logto :oidc-config :token_endpoint])]
     {:http-xhrio {:method :post
                   :uri token-endpoint
                   :body (query-string {:grant_type "authorization_code"
                                        :code code
                                        :client_id app-id
                                        :redirect_uri redirect-uri
                                        :code_verifier code-verifier})
                   :format (ajax/url-request-format)
                   :headers {"Content-Type" "application/x-www-form-urlencoded"}
                   :response-format (ajax/json-response-format {:keywords? true})
                   :on-success [::exchange-code-success]
                   :on-failure [::request-failed]}})))

(rf/reg-event-fx
 ::exchange-code-success
 (fn [{:keys [db]} [_ response]]
   (let [{:keys [access_token refresh_token id_token expires_in]} response
         now (js/Date.now)
         expires-at (+ now (* expires_in 1000))]
     {:db (-> db
              (assoc-in [:logto :tokens :id-token] id_token)
              (assoc-in [:logto :tokens :refresh-token] refresh_token)
              (assoc-in [:logto :tokens :access-tokens "default"]
                        {:token access_token :expires-at expires-at}))
      :fx [[:dispatch [::verify-id-token id_token]]
           [:dispatch [::get-user-info]]]})))

(rf/reg-event-fx
 ::verify-id-token
 (fn [{:keys [db]} [_ id-token]]
   (let [jwks (get-in db [:logto :jwks])
         parts (str/split id-token #"\.")
         header (js/JSON.parse (b64/decodeString (first parts)))
         claims (js/JSON.parse (b64/decodeString (second parts)))
         kid (:kid header)]
     ;; In a real implementation, you'd verify the signature using the JWK with matching kid
     ;; For simplicity, we're just checking claims here
     (if (and (< (js/Date.now) (* (:exp claims) 1000))
              (= (get-in db [:logto :config :app-id]) (:aud claims)))
       {:db (assoc-in db [:logto :id-token-claims] claims)}
       {:fx [[:dispatch [::sign-in-error "Invalid ID token"]]]}))))

(rf/reg-event-fx
 ::get-user-info
 (fn [{:keys [db]} _]
   (let [user-info-endpoint (get-in db [:logto :oidc-config :userinfo_endpoint])
         access-token (get-in db [:logto :tokens :access-tokens "default" :token])]
     {:http-xhrio {:method :get
                   :uri user-info-endpoint
                   :headers {"Authorization" (str "Bearer " access-token)}
                   :response-format (ajax/json-response-format {:keywords? true})
                   :on-success [::get-user-info-success]
                   :on-failure [::request-failed]}})))

(rf/reg-event-db
 ::get-user-info-success
 (fn [db [_ response]]
   (assoc-in db [:logto :user-info] response)))

(rf/reg-event-fx
 ::get-access-token
 (fn [{:keys [db]} [_ resource scopes]]
   (let [access-token-map (get-in db [:logto :tokens :access-tokens])
         token-info (get access-token-map resource)
         now (js/Date.now)]
     (if (and token-info (> (:expires-at token-info) now))
       {:db db} ; Token still valid
       {:fx [[:dispatch [::refresh-access-token resource scopes]]]}))))

(rf/reg-event-fx
 ::refresh-access-token
 (fn [{:keys [db]} [_ resource scopes]]
   (let [{:keys [app-id]} (get-in db [:logto :config])
         token-endpoint (get-in db [:logto :oidc-config :token_endpoint])
         refresh-token (get-in db [:logto :tokens :refresh-token])
         scope-param (when scopes (str/join " " scopes))]
     {:http-xhrio {:method :post
                   :uri token-endpoint
                   :body (query-string
                          (cond-> {:grant_type "refresh_token"
                                   :client_id app-id
                                   :refresh_token refresh-token}
                            resource (assoc :resource resource)
                            scope-param (assoc :scope scope-param)))
                   :format (ajax/url-request-format)
                   :headers {"Content-Type" "application/x-www-form-urlencoded"}
                   :response-format (ajax/json-response-format {:keywords? true})
                   :on-success [::refresh-token-success resource]
                   :on-failure [::request-failed]}})))

(rf/reg-event-db
 ::refresh-token-success
 (fn [db [_ resource response]]
   (let [{:keys [access_token refresh_token expires_in]} response
         now (js/Date.now)
         expires-at (+ now (* expires_in 1000))]
     (-> db
         (assoc-in [:logto :tokens :access-tokens resource]
                   {:token access_token :expires-at expires-at})
         (cond-> refresh_token (assoc-in [:logto :tokens :refresh-token] refresh_token))))))

(rf/reg-event-db
 ::sign-out
 (fn [db _]
   (update db :logto dissoc :tokens :user-info :id-token-claims)))

(rf/reg-event-db
 ::request-failed
 (fn [db [_ error]]
   (assoc-in db [:logto :error] error)))

;; --- Subscriptions ---
(rf/reg-sub
 ::config
 (fn [db _]
   (get-in db [:logto :config])))

(rf/reg-sub
 ::is-authenticated
 (fn [db _]
   (boolean (get-in db [:logto :tokens :id-token]))))

(rf/reg-sub
 ::user-info
 (fn [db _]
   (get-in db [:logto :user-info])))

(rf/reg-sub
 ::id-token
 (fn [db _]
   (get-in db [:logto :tokens :id-token])))

(rf/reg-sub
 ::access-token
 (fn [db [_ resource]]
   (let [resource-key (or resource "default")
         token-info (get-in db [:logto :tokens :access-tokens resource-key])]
     (when (and token-info (> (:expires-at token-info) (js/Date.now)))
       (:token token-info)))))

(rf/reg-sub
 ::error
 (fn [db _]
   (get-in db [:logto :error])))

;; --- Cookie fx ---
(rf/reg-fx
 :cookie/set
 (fn [{:keys [name value expires]}]
   (.set Cookies name value #js {:expires expires})))

(rf/reg-fx
 :cookie/remove
 (fn [name]
   (.remove Cookies name)))

(js/console.log "logto-client.core loaded")
