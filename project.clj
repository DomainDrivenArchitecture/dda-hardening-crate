(defproject dda/dda-hardening-crate "1.0.0-SNAPSHOT"
  :description "The dda hardening crate"
  :url "https://domaindrivenarchitecture.org"
  :license {:name "Apache License, Version 2.0"
            :url "https://www.apache.org/licenses/LICENSE-2.0.html"}
  :dependencies [[org.clojure/clojure "1.7.0"]
                 [dda/dda-pallet "2.1.0"]
                 [dda/dda-serverspec-crate "1.0.4-SNAPSHOT"]]
  :source-paths ["main/src"]
  :resource-paths ["main/resources"]
  :repositories [["snapshots" :clojars
                  ["releases" :clojars]]]
  :deploy-repositories [["snapshots" :clojars
                         ["releases" :clojars]]]
  :profiles {:dev {:source-paths ["integration/src"
                                  "test/src"
                                  "uberjar/src"]
                   :resource-paths ["integration/resources"
                                    "test/resources"]
                   :dependencies
                   [[org.domaindrivenarchitecture/pallet-aws "0.2.8.2"]
                    [org.clojure/test.check "0.10.0-alpha2"]
                    [com.palletops/pallet "0.8.12" :classifier "tests"]
                    [ch.qos.logback/logback-classic "1.3.0-alpha4"]
                    [org.slf4j/jcl-over-slf4j "1.8.0-beta2"]]
                   :plugins
                   [[lein-sub "0.3.0"]]
                   :leiningen/reply
                   {:dependencies [[org.slf4j/jcl-over-slf4j "1.8.0-beta0"]]
                    :exclusions [commons-logging]}
                   :repl-options {:init-ns dda.pallet.dda-hardening-crate.app.instantiate-aws}}
              :test {:test-paths ["test/src"]
                     :resource-paths ["test/resources"]
                     :dependencies [[com.palletops/pallet "0.8.12" :classifier "tests"]]}
              :uberjar {:source-paths ["uberjar/src"]
                        :resource-paths ["uberjar/resources"]
                        :aot :all
                        :main dda.pallet.dda-hardening-create.main
                        :dependencies [[org.clojure/tools.cli "0.3.5"]
                                       [ch.qos.logback/logback-classic "1.3.0-alpha4"]
                                       [org.slf4j/jcl-over-slf4j "1.8.0-beta2"]]}}
   :local-repo-classpath true)
