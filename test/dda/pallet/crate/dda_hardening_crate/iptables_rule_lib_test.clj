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

(ns dda.pallet.crate.dda-hardening-crate.iptables-rule-lib-test
 (:require
   [clojure.test :refer :all]
   [clojure.string :as string]
   [pallet.build-actions :as build-actions]
   [pallet.actions :as actions]
   [dda.pallet.crate.dda-hardening-crate.iptables-rule-lib :as sut]))


(def ^:private allow-ajp
  ["# allow incoming traffic from ip"
   "-A INPUT -p tcp -s 1.2.3.4 --dport 8009 -j ACCEPT"])

(deftest prefixtest
  (testing "filter prefix"
           (is (= ["*filter"
                   ":INPUT ACCEPT [0:0]"
                   ":FORWARD ACCEPT [0:0]"
                   ":OUTPUT ACCEPT [0:0]"]
                  (sut/prefix :filter)))
           (is (= ["*nat"
                   ":PREROUTING ACCEPT [0:0]"
                   ":OUTPUT ACCEPT [0:0]"
                   ":POSTROUTING ACCEPT [0:0]"]
                  (sut/prefix :nat)))
           (is (= ["*mangle"
                   ":PREROUTING ACCEPT [0:0]"
                   ":INPUT ACCEPT [0:0]"
                   ":FORWARD ACCEPT [0:0]"
                   ":OUTPUT ACCEPT [0:0]"
                   ":POSTROUTING ACCEPT [0:0]"]
                  (sut/prefix :mangle)))))


(deftest rule-antilockout
  (testing "antilockout"
           (is (= ["# ensure that incoming ssh works"
                   "-A INPUT -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT"
                   "-A OUTPUT -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT"]
                  sut/antilockout-rule))))


(deftest v4-drop-ping-rule
  (testing "v4-drop-ping-rule"
           (is (= ["-A FORWARD -p icmp -j DROP"]
                  (sut/v4-drop-ping-rule :foreward)))
           (is (= ["-A INPUT -p icmp -j DROP"]
                  (sut/v4-drop-ping-rule :input)))))


(deftest v6-drop-ping-rule
  (testing "v6-drop-ping-rule"
           (is (= ["-A FORWARD -p icmpv6 -j DROP"]
                  (sut/v6-drop-ping-rule :foreward)))
           (is (= ["-A INPUT -p icmpv6 -j DROP"]
                  (sut/v6-drop-ping-rule :input)))))


(deftest allow-established-rule
  (testing "allow-established-rule"
           (is (= ["# allow stablished connection for INPUT"
                   "-A INPUT -m state --state ESTABLISHED -j ACCEPT"]
                  (sut/allow-established-rule :input)))))



(deftest allow-destination-port-rule
  (testing "destination port"
           (is (= ["-A INPUT -p tcp --dport 80 -j ACCEPT"]
                  (sut/allow-destination-port-rule :input "tcp" "80")))
           (is (= ["-A OUTPUT -p tcp --dport 80 -j ACCEPT"]
                  (sut/allow-destination-port-rule :output "tcp" "80")))))


(deftest log-and-drop-rule
  (testing "log-and-drop-rule"
           (is (= ["# log and drop all the traffic for INPUT"
                   "-A INPUT -j LOG --log-level 4 --log-prefix \"INPUT DROP: \""
                   "-A INPUT -j DROP"]
                  (sut/log-and-drop-rule :input))))
  (testing "drop-output"
           (is (= ["# log and drop all the traffic for OUTPUT"
                   "-A OUTPUT -j LOG --log-level 4 --log-prefix \"OUTPUT DROP: \""
                   "-A OUTPUT -j DROP"]
                  (sut/log-and-drop-rule :output)))))


(deftest liferay-vhost
  (testing
    "test the good case"
    (is (= allow-ajp
           (sut/allow-ajp-from-ip "1.2.3.4")))))
