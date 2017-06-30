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

(ns dda.pallet.crate.dda-hardening-crate.iptables-config
  (:require
    [dda.pallet.crate.dda-hardening-crate.iptables-rule-lib :as rule-lib]))

(defn default-web-firewall
  []
  {:ipv4
   {:filter
    [rule-lib/allow-lo-rule
     rule-lib/antilockout-rule
     (rule-lib/allow-established-rule :input)
     (rule-lib/v4-drop-ping-rule :input)
     (rule-lib/allow-destination-port-rule
                       :input "tcp" "80")
     (rule-lib/allow-destination-port-rule
                       :input "tcp" "443")
     (rule-lib/log-and-drop-rule :input)
     (rule-lib/log-and-drop-rule :foreward)]}
   :ipv6
   {:filter
    [rule-lib/allow-lo-rule
     rule-lib/antilockout-rule
     (rule-lib/allow-destination-port-rule
                       :input "tcp" "443")
     (rule-lib/log-and-drop-rule :input)
     (rule-lib/log-and-drop-rule :foreward)]}})


(defn secure-firewall
  ""
  []
  {:ipv4
   {:filter
    [rule-lib/allow-lo-rule
     (rule-lib/antilockout-rule)
     (rule-lib/v4-drop-ping-rule :input)
     rule-lib/allow-ftp-as-client-rule
     rule-lib/allow-dns-as-client-rule
     (rule-lib/log-and-drop-rule :input)
     (rule-lib/allow-destination-port-rule :output "tcp" "80")
     (rule-lib/log-and-drop-rule :output)
     (rule-lib/log-and-drop-rule :foreward)]}
   :ipv6
   {:filter
    [rule-lib/allow-lo-rule
     (rule-lib/antilockout-rule)
     (rule-lib/v4-drop-ping-rule :input)
     rule-lib/allow-ftp-as-client-rule
     rule-lib/allow-dns-as-client-rule
     (rule-lib/log-and-drop-rule :input)
     (rule-lib/allow-destination-port-rule :output "tcp" "80")
     (rule-lib/log-and-drop-rule :output)
     (rule-lib/log-and-drop-rule :foreward)]}})
