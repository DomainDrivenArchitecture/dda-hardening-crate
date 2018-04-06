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

(ns dda.pallet.dda-hardening-crate.domain-test
  (:require
    [clojure.test :refer :all]
    [schema.core :as s]
    [dda.pallet.dda-hardening-crate.domain :as sut]))

(def config-1
  {:webserver {:additional-incomming-ports ["20"]}})

(def config-2
  {:all-tier-appserver {:additional-incomming-ports ["20"]
                        :allow-ajp-from-ip ["192.168.0.1"]}})

(def config-3
  {:ssh-only-server {:incomming-ports ["20"]}})

(def output-1 {:dda-hardening
               {:settings #{:unattende-upgrades :sshd-key-only}
                :iptables {:ip-version #{:ipv4 :ipv6}
                           :static-rules #{:antilockout-ssh :allow-local :drop-ping
                                           :allow-ftp-as-client :allow-dns-as-client
                                           :allow-established-output
                                           :log-and-drop-remaining-input}
                           :incomming-ports ["80" "443" "20"]}}})

(def output-2 {:dda-hardening
               {:settings #{:unattende-upgrades :sshd-key-only}
                :iptables {:ip-version #{:ipv4 :ipv6}
                           :static-rules #{:antilockout-ssh :allow-local :drop-ping
                                           :allow-ftp-as-client :allow-dns-as-client
                                           :allow-established-output
                                           :log-and-drop-remaining-input}
                           :incomming-ports ["80" "443" "20"]
                           :allow-ajp-from-ip ["192.168.0.1"]}}})

(def output-3 {:dda-hardening
               {:settings #{:unattende-upgrades :sshd-key-only}
                :iptables {:ip-version #{:ipv4 :ipv6}
                           :static-rules #{:antilockout-ssh :allow-local :drop-ping
                                           :allow-ftp-as-client :allow-dns-as-client
                                           :allow-established-output
                                           :log-and-drop-remaining-input}
                           :incomming-ports ["20"]}}})

(deftest test-infra-configure
  (testing
    "test the infra-config creaton"
    (is (thrown? Exception (sut/infra-configuration {})))
    (is (= (sut/infra-configuration config-1) output-1))
    (is (= (sut/infra-configuration config-2) output-2))
    (is (= (sut/infra-configuration config-3) output-3))))
