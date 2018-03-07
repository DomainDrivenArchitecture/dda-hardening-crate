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

(ns dda.pallet.dda-hardening-crate.infra.iptables-rule-lib
  (:require
    [pallet.actions :as actions]
    [pallet.crate :as crate]
    [clojure.string :as string]))


(defn- expand-chain
  ""
  [chain]
  (case chain
   :input "INPUT"
   :output "OUTPUT"
   :foreward "FORWARD"))


(defn- expand-table
  ""
  [table]
  (case table
   :filter "filter"
   :mangle "mangle"
   :nat "nat"))


(defn prefix
  ""
  [table]
  (case table
    :filter
    ["*filter"
     ":INPUT ACCEPT [0:0]"
     ":FORWARD ACCEPT [0:0]"
     ":OUTPUT ACCEPT [0:0]"]
    :mangle
    ["*mangle"
     ":PREROUTING ACCEPT [0:0]"
     ":INPUT ACCEPT [0:0]"
     ":FORWARD ACCEPT [0:0]"
     ":OUTPUT ACCEPT [0:0]"
     ":POSTROUTING ACCEPT [0:0]"]
    :nat
    ["*nat"
     ":PREROUTING ACCEPT [0:0]"
      ":OUTPUT ACCEPT [0:0]"
     ":POSTROUTING ACCEPT [0:0]"]))


(def suffix
  ["COMMIT"])


(def allow-lo-rule
  ["# allow local traffic"
   "-A INPUT -i lo -j ACCEPT"
   "-A OUTPUT -o lo -j ACCEPT"])


(def antilockout-rule
  ["# ensure that incoming ssh works"
   "-A INPUT -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT"
   "-A OUTPUT -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT"])


(defn v4-drop-ping-rule
  ""
  [chain]
  (let [chain-name (expand-chain chain)]
    [(str "-A " chain-name " -p icmp -j DROP")]))


(defn v6-drop-ping-rule
  ""
  [chain]
  (let [chain-name (expand-chain chain)]
    [(str "-A " chain-name " -p icmpv6 -j DROP")]))


(defn allow-ajp-from-ip
  [ip]
  ["# allow incoming traffic from ip"
   (str "-A INPUT -p tcp -s " ip " --dport 8009 -j ACCEPT")])

(def allow-ftp-as-client-rule
  ["# allow outgoing ftp requests"
   "-A INPUT -p tcp --sport 21 -m state --state ESTABLISHED -j ACCEPT"
   "-A INPUT -p tcp --sport 20 -m state --state ESTABLISHED,RELATED -j ACCEPT"
   "-A INPUT -p tcp --sport 1024: --dport 1024: -m state --state ESTABLISHED -j ACCEPT"
   "-A OUTPUT -p tcp --dport 21 -m state --state NEW,ESTABLISHED -j ACCEPT"
   "-A OUTPUT -p tcp --dport 20 -m state --state ESTABLISHED -j ACCEPT"
   "-A OUTPUT -p tcp --sport 1024: --dport 1024: -m state --state ESTABLISHED,RELATED,NEW -j ACCEPT"])


(def allow-dns-as-client-rule
  ["# allow outgoing dns requests"
   "-A OUTPUT -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT"
   "-A INPUT -p udp --sport 53 -m state --state ESTABLISHED -j ACCEPT"
   "-A OUTPUT -p tcp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT"
   "-A INPUT -p tcp --sport 53 -m state --state ESTABLISHED -j ACCEPT"])


(defn allow-established-rule
  ""
  [chain]
  (let [chain-name (expand-chain chain)]
    [(str "# allow stablished connection for " chain-name)
     (str "-A " chain-name " -m state --state ESTABLISHED -j ACCEPT")]))


(defn allow-destination-port-rule
  ""
  [chain protocol dport]
  (let [chain-name (expand-chain chain)]
    [(str "-A " chain-name " -p " protocol " --dport " dport " -j ACCEPT")]))



(defn log-and-drop-rule
  ""
  [chain]
  (let [chain-name (expand-chain chain)]
    [(str "# log and drop all the traffic for " chain-name)
     (str "-A " chain-name " -j LOG --log-level 4 --log-prefix \"" chain-name " DROP: \"")
     (str "-A " chain-name " -j DROP")]))
