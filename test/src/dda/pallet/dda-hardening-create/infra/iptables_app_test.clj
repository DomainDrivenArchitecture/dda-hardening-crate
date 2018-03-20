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

(ns dda.pallet.dda-hardening-crate.infra.iptables-app-test
 (:require
   [clojure.test :refer :all]
   [clojure.string :as string]
   [pallet.build-actions :as build-actions]
   [pallet.actions :as actions]
   [dda.pallet.dda-hardening-crate.infra.iptables-app :as sut]))


(def rules
  {:ipv4
   {:filter ["f1" "f2"]
    :mangle ["m1"]}
   :ipv6
   {:filter ["f1"]}})

(deftest chain-creation-test
  []
  (testing "filter"
    (is (= ["*filter"
            ":INPUT ACCEPT [0:0]"
            ":FORWARD ACCEPT [0:0]"
            ":OUTPUT ACCEPT [0:0]"
            "f1"
            "f2"
            "COMMIT"]
           (sut/create-chain-config :filter ["f1" "f2"]))))
  (testing "mangle"
    (is (= ["*mangle"
            ":PREROUTING ACCEPT [0:0]"
            ":INPUT ACCEPT [0:0]"
            ":FORWARD ACCEPT [0:0]"
            ":OUTPUT ACCEPT [0:0]"
            ":POSTROUTING ACCEPT [0:0]"
            "m1"
            "COMMIT"]
           (sut/create-chain-config :mangle ["m1"])))))


(deftest chains-creation-test
  []
  (testing "output for all provided chains"
    (is (= ["*filter"
            ":INPUT ACCEPT [0:0]"
            ":FORWARD ACCEPT [0:0]"
            ":OUTPUT ACCEPT [0:0]"
            "f1"
            "f2"
            "COMMIT"
            "*mangle"
            ":PREROUTING ACCEPT [0:0]"
            ":INPUT ACCEPT [0:0]"
            ":FORWARD ACCEPT [0:0]"
            ":OUTPUT ACCEPT [0:0]"
            ":POSTROUTING ACCEPT [0:0]"
            "m1"
            "COMMIT"]
           (sut/create-ip-config (:ipv4 rules))))))


(deftest persistent-iptables-test
  []
  (testing
    "ubuntu"
    (is
      (=
        (first
          (build-actions/build-actions
            {:server {:group-name :n :image {:os-family :ubuntu}}}
            (actions/remote-file
              "/etc/iptables/rules.v4"
              :overwrite-changes true
              :content
              (string/join
                \newline
                ["*filter"
                 ":INPUT ACCEPT [0:0]"
                 ":FORWARD ACCEPT [0:0]"
                 ":OUTPUT ACCEPT [0:0]"
                 "f1"
                 "f2"
                 "COMMIT"
                 "*mangle"
                 ":PREROUTING ACCEPT [0:0]"
                 ":INPUT ACCEPT [0:0]"
                 ":FORWARD ACCEPT [0:0]"
                 ":OUTPUT ACCEPT [0:0]"
                 ":POSTROUTING ACCEPT [0:0]"
                 "m1"
                 "COMMIT"]))
            (actions/remote-file
                  "/etc/iptables/rules.v6"
                  :overwrite-changes true
                  :content
                  (string/join
                    \newline
                    ["*filter"
                     ":INPUT ACCEPT [0:0]"
                     ":FORWARD ACCEPT [0:0]"
                     ":OUTPUT ACCEPT [0:0]"
                     "f1"
                     "COMMIT"]))))

        (first
          (build-actions/build-actions
            {:server {:group-name :n :image {:os-family :ubuntu}}}
            (sut/configure-iptables :rules rules)))))))
