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

(ns org.domaindrivenarchitecture.pallet.crate.hardening
 (:require
   [clojure.string :as string]
   [schema.core :as s]
   [pallet.actions :as actions]
   [pallet.api :as api]
   [pallet.crate :as crate]
   [pallet.stevedore :as stevedore]
   [org.domaindrivenarchitecture.pallet.core.dda-crate :as dda-crate]
   [org.domaindrivenarchitecture.pallet.crate.iptables :as iptables]
))

(def OssecConfig {:server-ip s/Str
                   :agent-key s/Str})

(def HardeningConfig {(s/optional-key :ossec) OssecConfig
                      (s/optional-key :iptables)
                      {:default s/Bool
                       (s/optional-key :custom-rules) [s/Str]}})

(def default-config
  {:iptables {:default true}})

(def dda-hardening-crate 
  (dda-crate/make-dda-crate
    :facility :dda-hardening
    :version [0 1 0]
    :config-schema HardeningConfig
    :config-default default-config
    ))

(defn ossec-agent-configuration
  [ossec-server-ip]
  ["<!------ Managed by pallet ------->"
   "<ossec_config>"
   "<client>"
   (str "  <server-ip>" ossec-server-ip "</server-ip>")
   "</client>"
   ""
   "<syscheck>"
   "  <!-- Frequency that syscheck is executed -- default every 2 hours -->"
   "  <frequency>7200</frequency>"
   "  " 
   "  <!-- Directories to check  (perform all possible verifications) -->"
   "  <directories check_all=\"yes\">/etc,/usr/bin,/usr/sbin</directories>"
   "  <directories check_all=\"yes\">/bin,/sbin</directories>"
   "  "
   "  <!-- Files/directories to ignore -->"
   "  <ignore>/etc/mtab</ignore>"
   "  <ignore>/etc/hosts.deny</ignore>"
   "  <ignore>/etc/mail/statistics</ignore>" 
   "  <ignore>/etc/random-seed</ignore>"
   "  <ignore>/etc/adjtime</ignore>"
   "  <ignore>/etc/httpd/logs</ignore>"
   "</syscheck>"
   ""
   "<rootcheck>"
   "  <rootkit_files>/var/ossec/etc/shared/rootkit_files.txt</rootkit_files>"
   "  <rootkit_trojans>/var/ossec/etc/shared/rootkit_trojans.txt</rootkit_trojans>"
   "</rootcheck>"
   ""
   "<localfile>"
   "  <log_format>syslog</log_format>"
   "  <location>/var/log/auth.log</location>"
   "</localfile>"
   ""
   ""
   "<localfile>"
   "  <log_format>apache</log_format>"
   "  <location>/var/log/apache2/access.log</location>"
   "</localfile>"
   ""
   "<localfile>"
   "  <log_format>apache</log_format>"
   "  <location>/var/log/apache2/ssl-access.log</location>"
   "</localfile>"
   ""
   "<localfile>"
   "  <log_format>apache</log_format>"
   "  <location>/var/log/apache2/other_vhosts_access.log</location>"
   "</localfile>"
   ""
   "<localfile>"
   "  <log_format>apache</log_format>"
   "  <location>/var/log/apache2/error.log</location>"
   "</localfile>"
   "</ossec_config>"
   ""]
  )

(defn configure-sshd
  ""
  []
  (actions/remote-file 
    "/etc/ssh/sshd_config" 
    :owner "root" 
    :group "root"
    :mode "644"
    :force true
    :local-file "./resources/org/domaindrivenarchitecture/pallet/crate/hardening/sshd_config"
    )
  )

(defn install-unattended-upgrades
  ""
  []
  (actions/package "unattended-upgrades")
)
 
(s/defn install-ossec
  "Install the ossec client"
  [config :- OssecConfig]
   (actions/package-source "ossec"
    :aptitude
    {:url "http://ossec.alienvault.com/repos/apt/ubuntu"
     :release "trusty"
     :key-url "http://ossec.alienvault.com/repos/apt/conf/ossec-key.gpg.key"
     :scopes ["main"]})
   (actions/package-manager :update)
   (actions/package "ossec-hids-agent")
)

(s/defn configure-ossec
  "configure the ossec client. Restart client is a missing feature."
  [config :- OssecConfig]
  (actions/exec
       {:language :bash}
       (stevedore/script
         ((str "echo \"y\n\"|" "/var/ossec/bin/manage_agents -i " ~(get-in config [:agent-key])))
       ))
  (actions/remote-file 
      "/var/ossec/etc/ossec.conf" 
      :owner "root" 
      :group "ossec"
      :mode "440"
      :force true
      :content (string/join
                 \newline
                 (ossec-agent-configuration (get-in config [:server-ip])))
      )
  ;  --------- neustart
  ;  bin/ossec-control restart
)

(s/defn install
  "installation of hardening crate"
  [config :- HardeningConfig]
  (install-unattended-upgrades)
  (when (contains? config :iptables)
    (iptables/install "iptables" {}))
  (when (contains? config :ossec)
    (install-ossec (get-in config [:ossec])))
  )

(s/defn configure 
  "configuration of hardening crate"
  [config :- HardeningConfig]
  (configure-sshd)
  (when (contains? config :iptables)
    ; TODO review jem 2016.06.22: migrate iptables to dda-pallet & schema
    (let [iptables-config (get-in config [:iptables])
          rules (if (get-in iptables-config [:default])
                  {}
                  {:rules (get-in iptables-config [:custom-rules])})]
    (iptables/configure "iptables" rules)))
  (when (contains? config :ossec)
    (configure-ossec (get-in config [:ossec])))
  )

(defmethod dda-crate/dda-install 
  :dda-hardening [dda-crate partial-effective-config]
  (let [config (dda-crate/merge-config dda-crate partial-effective-config)]
    (install config)))

(defmethod dda-crate/dda-configure 
  :dda-hardening [dda-crate partial-effective-config]
  (let [config (dda-crate/merge-config dda-crate partial-effective-config)]
    (configure config)))

(def with-hardening
  (dda-crate/create-server-spec dda-hardening-crate))