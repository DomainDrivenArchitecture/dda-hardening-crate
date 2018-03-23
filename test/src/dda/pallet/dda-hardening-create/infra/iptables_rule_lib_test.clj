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

(ns dda.pallet.dda-hardening-crate.infra.iptables-rule-lib-test
  (:require
   [clojure.string :as string]
   [clojure.test :refer :all]
   [schema.core :as s]
   [dda.pallet.dda-hardening-crate.infra.iptables-rule-lib :as sut]))

(def with-allow-established
  {:input {:ip-version #{:ipv4}
           :static-rules #{:antilockout-ssh :allow-local
                           :drop-ping :allow-ftp-as-client :allow-dns-as-client
                           :allow-established-input :allow-established-output
                           :log-and-drop-remaining-input
                           :log-and-drop-remaining-output}
           :allow-ajp-from-ip ["0.0.0.1" "0.0.0.2"]
           :incomming-ports ["80" "443"]
           :outgoing-ports ["443"]}
   :expected-ajp "
# allow incoming ajp traffic from ip
-A INPUT -p tcp -s 0.0.0.1 --dport 8009 -j ACCEPT
-A INPUT -p tcp -s 0.0.0.2 --dport 8009 -j ACCEPT"
   :expect-incomming-ports "
# allow incoming traffic for port
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT"})

(def without-allow-established
  {:input {:ip-version #{:ipv4}
           :static-rules #{:antilockout-ssh :allow-local
                           :drop-ping :allow-ftp-as-client :allow-dns-as-client
                           :log-and-drop-remaining-input
                           :log-and-drop-remaining-output}
           :allow-ajp-from-ip ["0.0.0.1" "0.0.0.2"]
           :incomming-ports ["80" "443"]
           :outgoing-ports ["443"]}
   :expected-ajp "
# allow incoming ajp traffic from ip
-A INPUT -p tcp -s 0.0.0.1 --dport 8009 -j ACCEPT
-A OUTPUT -p tcp -d 0.0.0.1 --sport 8009 --state ESTABLISHED -j ACCEPT
-A INPUT -p tcp -s 0.0.0.2 --dport 8009 -j ACCEPT
-A OUTPUT -p tcp -d 0.0.0.2 --sport 8009 --state ESTABLISHED -j ACCEPT"
   :expect-incomming-ports "
# allow incoming traffic for port
-A INPUT -p tcp --dport 80 -j ACCEPT
-A OUTPUT -p tcp --sport 80 --state ESTABLISHED -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT
-A OUTPUT -p tcp --sport 443 --state ESTABLISHED -j ACCEPT"})

(deftest allow-ajp-from-ip-test
  []
  (s/set-fn-validation! true)
  (testing "ajp with allow-established"
    (is (= (string/split-lines (:expected-ajp with-allow-established))
           (string/split-lines (sut/allow-ajp-from-ip (:input with-allow-established))))))
  (testing "incoming ports with allow-established"
    (is (= (string/split-lines (:expect-incomming-ports with-allow-established))
           (string/split-lines (sut/allow-incoming-port (:input with-allow-established))))))
  (testing "ajp without allow-established"
    (is (= (string/split-lines (:expected-ajp without-allow-established))
           (string/split-lines (sut/allow-ajp-from-ip (:input without-allow-established))))))
  (testing "incoming ports without allow-established"
    (is (= (string/split-lines (:expect-incomming-ports without-allow-established))
           (string/split-lines (sut/allow-incoming-port (:input without-allow-established)))))))
