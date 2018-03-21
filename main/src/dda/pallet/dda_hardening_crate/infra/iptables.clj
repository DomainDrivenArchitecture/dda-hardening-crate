; Licensed to the Apache Software Foundation (ASF) under one
; or more contributor license agreements. See the NOTICE file
; distributed with this work for additional information
; regarding copyright ownership. The ASF licenses this file
; to you under the Apache License, Version 2.0 (the
; "License"); you may not use this file except in compliance
; with the License. You may obtain a copy of the License at
;
; http://www.apache.org/licenses/LICENSE-2.0
;
; Unless required by applicable law or agreed to in writing, software
; distributed under the License is distributed on an "AS IS" BASIS,
; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
; See the License for the specific language governing permissions and
; limitations under the License.

(ns dda.pallet.dda-hardening-crate.infra.iptables
  (:require
    [clojure.string :as string]
    [schema.core :as s]
    [selmer.parser :as selmer]
    [pallet.actions :as actions]
    [pallet.crate :as crate]
    [pallet.stevedore :as stevedore]
    [dda.pallet.dda-hardening-crate.infra.iptables-rule-lib :as rule-lib]))


(def IpTables {:ip-version (hash-set (s/enum :ipv6 :ip4))
               :static-rules (hash-set (s/enum :antilockout-ssh :allow-local :drop-ping
                                               :allow-ftp-as-client :allow-dns-as-client
                                               :allow-established-input :log-and-drop-remaining-input
                                               :log-and-drop-remaining-output))
               (s/optional-key :allow-ajp-from-ip) [s/Str] ;incoming ip address
               (s/optional-key :incomming-ports) [s/Str]
               (s/optional-key :outgoing-ports) [s/Str]}) ; allow-destination-port)


(defn- write-iptables-file
  ""
  [file-name rules]
  (actions/remote-file
    file-name
    :overwrite-changes true
    :content
    (string/join
      \newline
      rules)))

(s/defn
  create-iptables-filter
  [ip-version :- s/Keyword
   infra-config :- IpTables]
  (selmer/render-file "ip_tables_filter.templ" infra-config))


(s/defn
  configure-iptables
  [infra-config :- IpTables]
  (let [v4-content (create-iptables-filter :ipv4 infra-config)
        v6-content ""]
    (write-iptables-file
      "/etc/iptables/rules.v4"
      v4-content)
    (write-iptables-file
      "/etc/iptables/rules.v6"
      v6-content)))


(defn reload-config
  []
  (actions/exec
      {:language :bash}
      (stevedore/script
        ("service netfilter-persistent restart"))))


(defn install-iptables
  ""
  []
  (actions/package "iptables-persistent"))
