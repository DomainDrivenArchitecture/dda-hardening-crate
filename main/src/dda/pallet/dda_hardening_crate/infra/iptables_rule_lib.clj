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

(defn allow-ajp-from-ip
  [ip]
  ["# allow incoming traffic from ip"
   (str "-A INPUT -p tcp -s " ip " --dport 8009 -j ACCEPT")])

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
