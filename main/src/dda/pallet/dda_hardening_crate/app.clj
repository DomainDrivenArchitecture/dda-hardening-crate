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

(ns dda.pallet.dda-hardening-crate.app
  (:require
   [schema.core :as s]
   [dda.config.commons.map-utils :as mu]
   [dda.pallet.core.app :as core-app]
   [dda.pallet.dda-serverspec-crate.app :as serverspec]
   [dda.pallet.dda-config-crate.infra :as config-crate]
   [dda.pallet.dda-hardening-crate.infra :as infra]
   [dda.pallet.dda-hardening-crate.domain :as domain]))

(def with-hardening infra/with-hardening)

(def InfraResult domain/InfraResult)

(def HardeningDomain domain/HardeningDomain)

(def HardeningAppConfig
  {:group-specific-config
   {s/Keyword
    (merge InfraResult
           serverspec/InfraResult)}})

(s/defn ^:always-validate
  app-configuration :- HardeningAppConfig
  [domain-config :- HardeningDomain
   & options]
  (let [{:keys [group-key]
         :or  {group-key infra/facility}} options]
    (mu/deep-merge
     (serverspec/app-configuration (domain/hardening-serverspec-config domain-config) :group-key group-key)
     {:group-specific-config
      {group-key (domain/infra-configuration domain-config)}})))

(s/defmethod ^:always-validate
  core-app/group-spec infra/facility
  [crate-app
   domain-config :- HardeningDomain]
  (let [app-config (app-configuration domain-config)]
    (core-app/pallet-group-spec
      app-config [(config-crate/with-config app-config)
                  serverspec/with-serverspec
                  with-hardening])))

(def crate-app (core-app/make-dda-crate-app
                  :facility infra/facility
                  :domain-schema HardeningDomain
                  :domain-schema-resolved HardeningDomain
                  :default-domain-file "hardening.edn"))
