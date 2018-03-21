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

(ns dda.pallet.dda-hardening-crate.infra.iptables-test
  (:require
   [clojure.test :refer :all]
   [dda.pallet.dda-hardening-crate.infra.iptables :as sut]))

(def pair1 {:input {}
            :expected "*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]

COMMIT
"})

(def pair2 {:input {:settings #{:ipv4 :drop-ping}}
            :expected "*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]

# drop v4 ping
-A INPUT  -p icmp -j DROP

COMMIT
"})

(def pair3 {:input {:settings #{:ipv4 :antilockout-ssh :allow-local :drop-ping
                                :allow-ftp-as-client :allow-dns-as-client
                                :allow-established :log-and-drop-remaining}}
            :expected "*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]

# ensure that incoming ssh works
-A INPUT -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

# drop v4 ping
-A INPUT  -p icmp -j DROP

# allow local traffic
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT

COMMIT
"})


(deftest chain-creation-test
  []
  (testing "filter"
    (is (= (:expected pair1)
           (sut/create-ip-version nil (:input pair1)))))
  (testing "filter"
    (is (= (:expected pair2)
           (sut/create-ip-version nil (:input pair2)))))
  (testing "filter"
    (is (= (:expected pair3)
           (sut/create-ip-version nil (:input pair3))))))
