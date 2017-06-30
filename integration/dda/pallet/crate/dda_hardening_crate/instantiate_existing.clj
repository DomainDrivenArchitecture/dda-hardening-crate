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

(ns dda.pallet.crate.dda-hardening-crate.instantiate-existing
  (:require
    [clojure.inspector :as inspector]
    [org.domaindrivenarchitecture.pallet.commons.session-tools :as session-tools]
    [org.domaindrivenarchitecture.pallet.commons.pallet-schema :as ps]
    [dda.cm.operation :as operation]
    [dda.cm.existing :as existing]
    [dda.pallet.domain.hardening :as domain]))

(def provisioning-ip
  "192.168.56.103")

(def provisioning-user
  {:login "jem"
   :password "test1234"})

(def domain-config {})

(defn provider []
  (existing/provider provisioning-ip "node-id" "dda-servertest-group"))

(defn integrated-group-spec []
  (merge
    (domain/dda-hardening-group (domain/crate-stack-configuration domain-config))
    (existing/node-spec provisioning-user)))

(defn apply-install []
  (operation/do-apply-install (provider) (integrated-group-spec)))

(defn apply-config []
  (operation/do-apply-configure (provider) (integrated-group-spec)))

(defn server-test []
  (operation/do-server-test (provider) (integrated-group-spec)))
