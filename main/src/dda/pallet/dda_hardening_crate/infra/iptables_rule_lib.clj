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

(ns dda.pallet.dda-hardening-crate.infra.iptables-rule-lib
  (:require
    [clojure.string :as string]
    [schema.core :as s]
    [pallet.actions :as actions]
    [pallet.crate :as crate]
    [clojure.string :as string]))

(def IpVersion (s/enum :ipv6 :ip4))

(def IpTables {:ip-version (hash-set IpVersion)
               :static-rules (hash-set (s/enum :antilockout-ssh :allow-local :drop-ping
                                               :allow-ftp-as-client :allow-dns-as-client
                                               :allow-established-input :allow-established-output
                                               :log-and-drop-remaining-input :log-and-drop-remaining-output))
               (s/optional-key :allow-ajp-from-ip) [s/Str] ;incoming ip address
               (s/optional-key :incomming-ports) [s/Str]
               (s/optional-key :outgoing-ports) [s/Str]}) ; allow-destination-port)

(s/defn
  allow-ajp-from-single-ip :- s/Str
  [allow-established-output :- s/Bool
   ip :- s/Str]
  (into
    [(str "-A INPUT -p tcp -s " ip " --dport 8009 -j ACCEPT")]
    (when (not allow-established-output)
      [(str "-A OUTPUT -p tcp -d " ip " --sport 8009 --state ESTABLISHED -j ACCEPT")])))

(s/defn
  allow-ajp-from-ip :- s/Str
  [config :- IpTables]
  (let [{:keys [static-rules allow-ajp-from-ip]} config
        {:keys [allow-established-output]} static-rules]
    (string/join
      \newline
      (flatten
        (conj
          [""
           "# allow incoming ajp traffic from ip"]
          (map (partial allow-ajp-from-single-ip allow-established-output) allow-ajp-from-ip))))))

(defn allow-destination-port-rule
  ""
  [chain protocol dport]
  (let [chain-name "x"]
    [(str "-A " chain-name " -p " protocol " --dport " dport " -j ACCEPT")]))
