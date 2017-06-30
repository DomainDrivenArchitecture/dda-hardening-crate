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

(ns dda.pallet.domain.hardening
 (:require
   [schema.core :as s]
   [dda.cm.group :as group]
   [dda.pallet.core.dda-crate :as dda-crate]
   [dda.pallet.crate.config :as config-crate]
   [dda.pallet.crate.hardening :as hardening-crate]))

(def HardeningDomainConfig
 {})

(def HardeningCrateStackConfig
  {:group-specific-config
   {s/Keyword {hardening-crate/facility
               hardening-crate/HardeningConfig}}})

(defn crate-stack-configuration [domain-config
                                 & {:keys [group-key] :or {group-key :dda-hardening-group}}]
  (s/validate s/Keyword group-key)
  (s/validate HardeningDomainConfig domain-config)
  (s/validate
     HardeningCrateStackConfig
     {:group-specific-config
        {group-key
         {hardening-crate/facility
          {:iptables {:default true}}}}}))

(def with-hardening
 (dda-crate/create-server-spec hardening-crate/dda-hardening-crate))

(defn dda-hardening-group [stack-config]
  (group/create-group
    stack-config
    [(config-crate/with-config stack-config)
     with-hardening]))
