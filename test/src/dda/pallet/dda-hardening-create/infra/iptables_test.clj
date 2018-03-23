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
   [clojure.string :as string]
   [clojure.test :refer :all]
   [schema.core :as s]
   [dda.pallet.dda-hardening-crate.infra.iptables :as sut]))

(def empty-config {:input {}
                   :expected "*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]

COMMIT
"})

(def drop-v4 {:input {:ip-version #{:ipv4}
                      :static-rules #{:ipv4 :drop-ping}}
              :expected "*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]

# drop v4 ping
-A INPUT  -p icmp -j DROP

COMMIT
"})

(def full-wo-established {:input {:ip-version #{:ipv4}
                                  :static-rules #{:antilockout-ssh :allow-local
                                                  :drop-ping :allow-ftp-as-client :allow-dns-as-client
                                                  :log-and-drop-remaining-input
                                                  :log-and-drop-remaining-output}
                                  :allow-ajp-from-ip ["0.0.0.1" "0.0.0.2"]
                                  :incomming-ports ["80" "443"]
                                  :outgoing-ports ["443"]}
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

# allow incoming ajp traffic from ip
-A INPUT -p tcp -s 0.0.0.1 --dport 8009 -j ACCEPT
-A OUTPUT -p tcp -d 0.0.0.1 --sport 8009 --state ESTABLISHED -j ACCEPT
-A INPUT -p tcp -s 0.0.0.2 --dport 8009 -j ACCEPT
-A OUTPUT -p tcp -d 0.0.0.2 --sport 8009 --state ESTABLISHED -j ACCEPT

# allow incoming traffic for port
-A INPUT -p tcp --dport 80 -j ACCEPT
-A OUTPUT -p --sport 80 --state ESTABLISHED -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT
-A OUTPUT -p tcp --sport 443 --state ESTABLISHED -j ACCEPT

# allow outgoing traffic for port
-A OUTPUT -p tcp --dport 443 -j ACCEPT
-A INPUT -p tcp --sport 443 --state ESTABLISHED -j ACCEPT

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

(def full-with-established {:input {:ip-version #{:ipv4}
                                    :static-rules #{:antilockout-ssh :allow-local
                                                    :drop-ping :allow-ftp-as-client :allow-dns-as-client
                                                    :allow-established-input :allow-established-output
                                                    :log-and-drop-remaining-input
                                                    :log-and-drop-remaining-output}
                                    :allow-ajp-from-ip ["0.0.0.1" "0.0.0.2"]
                                    :incomming-ports ["80" "443"]
                                    :outgoing-ports ["443"]}
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

# allow incoming ajp traffic from ip
-A INPUT -p tcp -s 0.0.0.1 --dport 8009 -j ACCEPT
-A INPUT -p tcp -s 0.0.0.2 --dport 8009 -j ACCEPT

# allow incoming traffic for port
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT

# allow outgoing traffic for port
-A OUTPUT -p tcp --dport 443 -j ACCEPT

# allow outgoing dns requests
-A OUTPUT -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT

# allow outgoing ftp requests
-A INPUT -p tcp --sport 21 -m state --state ESTABLISHED -j ACCEPT
-A INPUT -p tcp --sport 20 -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp --sport 1024: --dport 1024: -m state --state ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp --dport 21 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp --dport 20 -m state --state ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp --sport 1024: --dport 1024: -m state --state ESTABLISHED,RELATED,NEW -j ACCEPT

# allow stablished connection for INPUT
-A INPUT -m state --state ESTABLISHED -j ACCEPT

# allow stablished connection for OUTPUT
-A OUTPUT -m state --state ESTABLISHED -j ACCEPT

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
  (s/set-fn-validation! true)
  (testing "empty-config"
    (is (= (string/split-lines (:expected empty-config))
           (string/split-lines (sut/create-iptables-filter :ipv4 (:input empty-config))))))
  (testing "drop-v4"
    (is (= (string/split-lines (:expected drop-v4))
           (string/split-lines (sut/create-iptables-filter :ipv4 (:input drop-v4))))))
  (testing "full-wo-established"
    (is (= (string/split-lines (:expected full-wo-established))
           (string/split-lines (sut/create-iptables-filter :ipv4 (:input full-wo-established))))))
  (testing "full-with-established"
    (is (= (string/split-lines (:expected full-with-established))
           (string/split-lines (sut/create-iptables-filter :ipv4 (:input full-with-established)))))))
