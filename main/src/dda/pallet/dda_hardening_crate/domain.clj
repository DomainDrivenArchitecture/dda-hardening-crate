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
  (let [{:keys [versiom ports ping]} domain-config]
    {infra/facility domain-config}))
