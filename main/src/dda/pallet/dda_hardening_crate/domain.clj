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
    {:webserver {:additional-incomming-ports [s/Str]}}
    {:appserver {:additional-incomming-ports [s/Str]
                 :allow-ajp-from-ip [s/Str]}}
    {:ssh-only-server {:incomming-ports [s/Str]}}))

(def web-server-default
 {:settings #{:unattende-upgrades :sshd-key-only}
  :iptables {:settings #{:ip-v6 :antilockout-ssh :v4-drop-ping
                          :allow-dns-as-client :allow-established :log-and-drop-remaining}}
  :incomming-ports ["80" "443"]})

(def HardeningDomainResolved
  (secret/create-resolved-schema HardeningDomain))

(s/defn ^:always-validate
  infra-configuration :- InfraResult
  [domain-config :- HardeningDomainResolved]
  (let [{:keys [settings iptables incomming-ports]} web-server-default]
    {infra/facility
     (merge
       {:settings
        (hash-set
          (when (contains? settings :unattende-upgrades)
           :unattende-upgrades)
          (when (contains? settings :sshd-key-only)
           :sshd-key-only))}
       (when (contains? web-server-default :iptables)
        {:iptables
         (merge
           {:ip-version
             (if (contains? (:settings iptables) :ip-v4)
              (hash-set :ipv4) (hash-set :ipv6))}
           {:static-rules
            (hash-set
             (when (contains? web-server-default :antilockout-ssh)
              :antilockout-ssh)
             (when (contains? web-server-default :v4-drop-ping)
              :drop-ping)
             (when (contains? web-server-default :allow-dns-as-client)
              :allow-dns-as-client)
             (when (contains? web-server-default :allow-ftp-as-client)
              :allow-ftp-as-client)
             (when (contains? web-server-default :allow-established)
              :allow-established-input :allow-established-output)
             (when (contains? web-server-default :log-and-drop-remaining)
              :log-and-drop-remaining-input :log-and-drop-remaining-output))}
           (cond
             (contains? domain-config :appserver) {:allow-ajp-from-ip (:allow-ajp-from-ip (:appserver domain-config))
                                                   :incomming-ports (concat
                                                                     incomming-ports
                                                                     (:additional-incomming-ports (:appserver domain-config)))}
             (contains? domain-config :webserver) {:incomming-ports (concat
                                                                     incomming-ports
                                                                     (:additional-incomming-ports (:webserver domain-config)))}
             (contains? domain-config :ssh-only-server) {:incomming-ports (:incomming-ports (:ssh-only-server domain-config))})
           (when (contains? web-server-default :outgoing-ports)
             {:outgoing-ports (:outgoing-ports web-server-default)}))}))}))

