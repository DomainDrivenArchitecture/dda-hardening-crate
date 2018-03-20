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

(ns dda.pallet.dda-hardening-crate.infra
 (:require
   [clojure.string :as string]
   [clojure.tools.logging :as logging]
   [schema.core :as s]
   [pallet.actions :as actions]
   [pallet.crate :as crate]
   [dda.pallet.dda-hardening-crate.infra.iptables :as iptables]
   [dda.pallet.dda-hardening-crate.infra.iptables-config :as iptables-config]
   [dda.pallet.dda-hardening-crate.infra.sshd :as sshd]
   [dda.pallet.core.dda-crate :as dda-crate]))

(def facility :dda-hardening)
(def version [0 4 0])

(def HardeningInfra
 {:settings (hash-set (s/enum :unattende-upgrades
                              :sshd-key-only))
  (s/optional-key :iptables) iptables/IpTables})

(def dda-hardening-crate
  (dda-crate/make-dda-crate
    :facility facility
    :version version))

(def with-hardening
  (dda-crate/create-server-spec dda-hardening-crate))

(defn install-unattended-upgrades []
  (actions/package "unattended-upgrades"))

(s/defn install
  "installation of hardening crate"
  [config :- HardeningConfig]
  (actions/as-action
      (logging/info (str "12345")))
  (install-unattended-upgrades)
  (when (contains? config :iptables)
    (iptables/install-iptables)))

(s/defn configure
  "configuration of hardening crate"
  [config :- HardeningConfig]
  (sshd/configure-sshd)
  (when (contains? config :iptables)
    (let [iptables-config (get-in config [:iptables])
          rules (if (get-in iptables-config [:default])
                  (iptables-config/default-web-firewall)
                  (get-in iptables-config [:custom-rules]))]
     (iptables/configure-iptables :rules rules))))

(s/defmethod dda-crate/dda-install facility
  [dda-crate config]
  (install config))

(s/defmethod dda-crate/dda-configure facility
  [dda-crate config]
  (configure config))
