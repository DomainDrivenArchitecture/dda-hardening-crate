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

(ns dda.pallet.dda-hardening-crate.domain
 (:require
   [schema.core :as s]
   [dda.pallet.commons.secret :as secret]
   [dda.pallet.dda-hardening-crate.infra :as infra]))

(def InfraResult {infra/facility infra/HardeningInfra})

(def HardeningDomain
  (s/either
    {:webserver                ; block incoming traffic except 22, 80 & 443
          {:additional-incomming-ports [s/Str]}}
    {:all-tier-appserver       ; block incoming traffic except 22, 80 & 443, allow ajp from known ip
        {:additional-incomming-ports [s/Str]
         :allow-ajp-from-ip [s/Str]}}
    {:ssh-only-server          ; block incoming traffic except 22
        {:incomming-ports [s/Str]}}))

(def HardeningDomainResolved
  (secret/create-resolved-schema HardeningDomain))

(s/defn ^:always-validate
  infra-configuration :- InfraResult
  [domain-config :- HardeningDomainResolved]
  (let [{:keys [webserver all-tier-appserver ssh-only-server]} domain-config]
    {infra/facility
     (cond
       (contains? domain-config :webserver)
       {:settings #{:unattende-upgrades :sshd-key-only}
        :iptables {:ip-version #{:ipv4 :ipv6}
                   :static-rules #{:antilockout-ssh :allow-local :drop-ping
                                   :allow-ftp-as-client :allow-dns-as-client
                                   :allow-established-output
                                   :log-and-drop-remaining-input}
                   :incomming-ports (into
                                      ["80" "443"]
                                      (:additional-incomming-ports webserver))}}
       (contains? domain-config :all-tier-appserver)
       {:settings #{:unattende-upgrades :sshd-key-only}
        :iptables {:ip-version #{:ipv4 :ipv6}
                   :static-rules #{:antilockout-ssh :allow-local :drop-ping
                                   :allow-ftp-as-client :allow-dns-as-client
                                   :allow-established-output
                                   :log-and-drop-remaining-input}
                   :incomming-ports (into
                                      ["80" "443"]
                                      (:additional-incomming-ports all-tier-appserver))
                   :allow-ajp-from-ip (:allow-ajp-from-ip all-tier-appserver)}}
      (contains? domain-config :ssh-only-server)
      {:settings #{:unattende-upgrades :sshd-key-only}
       :iptables {:ip-version #{:ipv4 :ipv6}
                  :static-rules #{:antilockout-ssh :allow-local :drop-ping
                                  :allow-ftp-as-client :allow-dns-as-client
                                  :allow-established-output
                                  :log-and-drop-remaining-input}
                  :incomming-ports (:incomming-ports ssh-only-server)}})}))

(s/defn ^:always-validate
  hardening-serverspec-config
  [domain-config :- HardeningDomainResolved]
  {:file [{:path "/etc/iptables/rules.v4"}
          {:path "/etc/iptables/rules.v6"}]})
