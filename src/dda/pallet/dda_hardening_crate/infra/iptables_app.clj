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

(ns dda.pallet.dda-hardening-crate.infra.iptables-app
  (:require
    [clojure.string :as string]
    [pallet.actions :as actions]
    [pallet.crate :as crate]
    [pallet.stevedore :as stevedore]
    [dda.pallet.dda-hardening-crate.infra.iptables-rule-lib :as rule-lib]
    [dda.pallet.dda-hardening-crate.infra.iptables-config :as config]))


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


(defn create-chain-config
  ""
  [chain chain-rules]
  (concat
    (rule-lib/prefix chain)
    chain-rules
    rule-lib/suffix))


(defn create-ip-config
  ""
  [rule-map-by-chain]
  (into
    []
    (flatten
      (for [[k v] rule-map-by-chain] (create-chain-config k v)))))


(defn configure-iptables
  [& {:keys [rules]
      :or {rules (config/default-web-firewall)}}]
  (let [v4-content (create-ip-config (:ipv4 rules))
        v6-content (create-ip-config (:ipv6 rules))]
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
