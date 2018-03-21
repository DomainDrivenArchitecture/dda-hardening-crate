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

(def pair3 {:input {:settings #{:ip4 :antilockout-ssh :allow-local
                                :drop-ping :allow-ftp-as-client :allow-dns-as-client
                                :allow-established-input :log-and-drop-remaining-input
                                :log-and-drop-remaining-output}}
            :expected "*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]

# ensure that incoming ssh works
-A INPUT -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

# allow local traffic
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT

# allow stablished connection for INPUT
-A INPUT -m state --state ESTABLISHED -j ACCEPT

# allow outgoing dns requests
-A OUTPUT -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
-A INPUT -p udp --sport 53 -m state --state ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
-A INPUT -p tcp --sport 53 -m state --state ESTABLISHED -j ACCEPT

# allow outgoing ftp requests
-A INPUT -p tcp --sport 21 -m state --state ESTABLISHED -j ACCEPT
-A INPUT -p tcp --sport 20 -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp --sport 1024: --dport 1024: -m state --state ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp --dport 21 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp --dport 20 -m state --state ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp --sport 1024: --dport 1024: -m state --state ESTABLISHED,RELATED,NEW -j ACCEPT

# log and drop all the traffic for INPUT
-A INPUT -j LOG --log-level 4 --log-prefix \"INPUT DROP: \"
-A INPUT -j DROP

# log and drop all the traffic for OUTPUT
-A OUTPUT -j LOG --log-level 4 --log-prefix \"OUTPUT DROP: \"
-A OUTPUT -j DROP

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
