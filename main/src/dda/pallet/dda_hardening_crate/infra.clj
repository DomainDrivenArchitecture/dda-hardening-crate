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
   [dda.pallet.core.infra :as core-infra]
   [dda.pallet.dda-hardening-crate.infra.iptables :as iptables]
   [dda.pallet.dda-hardening-crate.infra.sshd :as sshd]))

(def facility :dda-hardening)

(def HardeningInfra
 {:settings (hash-set (s/enum :unattende-upgrades
                              :sshd-key-only))
  (s/optional-key :iptables) iptables/IpTables})

(defn install-unattended-upgrades []
  (actions/package "unattended-upgrades"))

(s/defn ^:always-validate
  install
  "installation of hardening crate"
  [config :- HardeningInfra]
  (let [{:keys [settings]} config]
    (when (contains? settings :unattende-upgrades)
      (install-unattended-upgrades))
    (when (contains? config :iptables)
      (iptables/install-iptables))))

(s/defn ^:always-validate 
  configure
  "configuration of hardening crate"
  [config :- HardeningInfra]
  (let [{:keys [settings iptables]} config]
    (when (contains? settings :sshd-key-only)
      (sshd/configure-sshd))
    (when (contains? config :iptables)
      (iptables/configure-iptables iptables))))

(s/defmethod
  core-infra/dda-install facility
  [core-infra config]
  (install config))

(s/defmethod
  core-infra/dda-configure facility
  [core-infra config]
  (configure config))

(def dda-hardening-crate
  (core-infra/make-dda-crate-infra
   :facility facility))

(def with-hardening
  (core-infra/create-infra-plan dda-hardening-crate))
