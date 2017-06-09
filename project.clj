(defproject dda/dda-hardening-crate "0.2.0-SNAPSHOT"
  :description "The dda hrdening crate"
  :url "https://domaindrivenarchitecture.org"
  :pallet {:source-paths ["src"]}
  :license {:name "Apache License, Version 2.0"
            :url "https://www.apache.org/licenses/LICENSE-2.0.html"}
  :dependencies [[org.clojure/clojure "1.7.0"]
                 [com.palletops/pallet "0.8.12"]
                 [dda/dda-pallet "0.4.0-SNAPSHOT"]
                 [dda/dda-iptables-crate "0.3.0-SNAPSHOT"]]
   :repositories [["snapshots" :clojars]
                  ["releases" :clojars]]
   :deploy-repositories [["snapshots" :clojars]
                         ["releases" :clojars]]
  :profiles {:dev
             {:dependencies
              [[com.palletops/pallet "0.8.12" :classifier "tests"]
               [org.domaindrivenarchitecture/dda-pallet-commons "0.3.0" :classifier "tests"]]
              :plugins
              [[com.palletops/pallet-lein "0.8.0-alpha.1"]
               [lein-sub "0.3.0"]]}
             :leiningen/reply
               {:dependencies [[org.slf4j/jcl-over-slf4j "1.7.22"]]
                :exclusions [commons-logging]}}
   :local-repo-classpath true
   :classifiers {:tests {:source-paths ^:replace ["test"]
                         :resource-paths ^:replace []}})
