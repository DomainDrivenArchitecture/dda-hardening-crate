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

(def IpVersion rule-lib/IpVersion)

(def IpTables rule-lib/IpTables)

(s/defn
  create-iptables-filter
  [ip-version :- IpVersion
   infra-config :- IpTables]
  (let [{:keys [allow-ajp-from-ip]} infra-config
        enriched-config (merge
                          infra-config
                          {:ip-version {ip-version true}}
                          {:dynamic-rules
                           {:allow-ajp-from-ip (rule-lib/allow-ajp-from-ip infra-config)
                            :incomming-ports (rule-lib/allow-incoming-port infra-config)}})]
    (selmer/render-file "ip_tables_filter.templ" enriched-config)))

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
