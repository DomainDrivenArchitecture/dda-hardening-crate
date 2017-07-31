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
   [schema.core :as s]
   [pallet.actions :as actions]
   [pallet.crate :as crate]
   [dda.pallet.dda-hardening-crate.infra.iptables-app :as iptables]
   [dda.pallet.dda-hardening-crate.infra.iptables-config :as iptables-config]
   [dda.pallet.dda-hardening-crate.infra.ossec :as ossec]
   [dda.pallet.dda-hardening-crate.infra.sshd :as sshd]
   [dda.pallet.core.dda-crate :as dda-crate]))

(def facility :dda-hardening)
(def version [0 2 0])

(def HardeningConfig {(s/optional-key :ossec) ossec/OssecConfig
                      (s/optional-key :iptables)
                      {:default s/Bool (s/optional-key :custom-rules) [s/Str]}})


(def default-config
  {:iptables {:default true}})

(def dda-hardening-crate
  (dda-crate/make-dda-crate
    :facility facility
    :version version
    :config-schema HardeningConfig
    :config-default default-config))

(defn install-unattended-upgrades []
  (actions/package "unattended-upgrades"))

(s/defn install
  "installation of hardening crate"
  [config :- HardeningConfig]
  (install-unattended-upgrades)
  (when (contains? config :iptables)
    (iptables/install-iptables))
  (when (contains? config :ossec)
    (ossec/install-ossec (get-in config [:ossec]))))

(s/defn configure
  "configuration of hardening crate"
  [config :- HardeningConfig]
  (sshd/configure-sshd)
  (when (contains? config :iptables)
    (let [iptables-config (get-in config [:iptables])
          rules (if (get-in iptables-config [:default])
                  (iptables-config/default-web-firewall)
                  (get-in iptables-config [:custom-rules]))]
     (iptables/configure-iptables :rules rules)))
  (when (contains? config :ossec)
    (ossec/configure-ossec (get-in config [:ossec]))))

(defmethod dda-crate/dda-install
  facility [dda-crate partial-effective-config]
  (let [config (dda-crate/merge-config dda-crate partial-effective-config)]
    (install config)))

(defmethod dda-crate/dda-configure
  facility [dda-crate partial-effective-config]
  (let [config (dda-crate/merge-config dda-crate partial-effective-config)]
    (configure config)))
