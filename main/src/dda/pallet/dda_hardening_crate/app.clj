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
   [dda.cm.group :as group]
   [dda.config.commons.map-utils :as mu]
   [dda.pallet.commons.secret :as secret]
   [dda.pallet.commons.existing :as existing]
   [dda.pallet.dda-config-crate.infra :as config-crate]
   [dda.pallet.dda-hardening-crate.infra :as infra]
   [dda.pallet.dda-hardening-crate.domain :as domain]
   [dda.pallet.commons.external-config :as ext-config]))

(def with-hardening infra/with-hardening)
(def InfraResult domain/InfraResult)
(def HardeningDomainConfig domain/HardeningDomainConfig)
(def HardeningResolvedConfig domain/HardeningResolvedConfig)

(def ProvisioningUser existing/ProvisioningUser)
(def Targets existing/Targets)

(def HardeningAppConfig
  {:group-specific-config
   {s/Keyword (merge InfraResult)}})

(s/defn ^:always-validate load-targets :- Targets
  [file-name :- s/Str]
  (existing/load-targets file-name))

(s/defn ^:always-validate load-domain :- HardeningDomainConfig
  [file-name :- s/Str]
  (ext-config/parse-config file-name))

(s/defn dda-hardening-group-spec
  [app-config :- HardeningAppConfig]
  (group/group-spec
    app-config [(config-crate/with-config app-config)
                with-hardening]))

(s/defn ^:always-validate
  app-configuration-resolved :- HardeningAppConfig
  [resolved-domain-config :- HardeningResolvedConfig & options]
  (let [{:keys [group-key] :or {group-key infra/facility}} options
        {:keys [type]} resolved-domain-config]
     {:group-specific-config {group-key (domain/infra-configuration resolved-domain-config)}}))

(s/defn ^:always-validate
  app-configuration :- HardeningAppConfig
  [domain-config :- HardeningDomainConfig & options]
  (let [resolved-domain-config (secret/resolve-secrets domain-config HardeningDomainConfig)]
    (apply app-configuration-resolved resolved-domain-config options)))

(s/defn ^:always-validate
  existing-provisioning-spec-resolved
  "Creates an integrated group spec from a domain config and a provisioning user."
  [domain-config :- HardeningDomainConfig
   targets-config :- existing/TargetsResolved]
  (let [{:keys [existing provisioning-user]} targets-config]
    (merge
     (dda-hardening-group-spec (app-configuration domain-config))
     (existing/node-spec provisioning-user))))

(s/defn ^:always-validate
  existing-provisioning-spec
  "Creates an integrated group spec from a domain config and a provisioning user."
  [domain-config :- HardeningDomainConfig
   targets-config :- existing/Targets]
  (existing-provisioning-spec-resolved domain-config (existing/resolve-targets targets-config)))

(s/defn ^:always-validate existing-provider-resolved
  [targets-config :- existing/TargetsResolved]
  (let [{:keys [existing provisioning-user]} targets-config]
    (existing/provider {:dda-hardening existing})))

(s/defn ^:always-validate existing-provider
  [targets-config :- existing/Targets]
  (existing-provider-resolved (existing/resolve-targets targets-config)))
