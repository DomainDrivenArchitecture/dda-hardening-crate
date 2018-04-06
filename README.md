# dda-hardening-crate
[![Clojars Project](https://img.shields.io/clojars/v/dda/dda-hardening-crate.svg)](https://clojars.org/dda/dda-hardening-crate)
[![Build Status](https://travis-ci.org/DomainDrivenArchitecture/dda-hardening-crate.svg?branch=master)](https://travis-ci.org/DomainDrivenArchitecture/dda-hardening-cratet)

[![Slack](https://img.shields.io/badge/chat-clojurians-green.svg?style=flat)](https://clojurians.slack.com/messages/#dda-pallet/) | [<img src="https://domaindrivenarchitecture.org/img/meetup.svg" width=50 alt="DevOps Hacking with Clojure Meetup"> DevOps Hacking with Clojure](https://www.meetup.com/de-DE/preview/dda-pallet-DevOps-Hacking-with-Clojure) | [Website & Blog](https://domaindrivenarchitecture.org)

## Jump to
[Usage](#usage)
[Reference-Targets](#targets)
[Reference-Domain-API](#domain-api)
[Reference-Infra-API](#infra-api)
[Compatibility](#compatibility)
[License](#license)

## Features
* uses iptables-persistent
* provides ipv4 & ipv6 support
* prebuild rules for antilockout-ssh, drop-ping (also fine grained on ipv6), allow-ftp-as-client, allow-dns-as-client, ...
* ubuntu unattended upgrades
* sshd hardening

## Usage
1. **Download the jar-file** from the releases page of this repository (e.g. `curl -L -o /serverspec.jar https://github.com/DomainDrivenArchitecture/dda-hardening-crate/releases/download/1.0.0/dda-hardening-crate-1.0.0-standalone.jar`)
2. **Create the ```hardening.edn``` configruration** file in the same folder where you saved the jar-file. The ```hardening.edn``` file specifies the hardenings to apply. You may use the following example as a starting point and adjust it according to your own needs:

```clojure
{:webserver
    {:additional-incomming-ports ["23442"]}}
  ```
3. (optional) If you want to perform the tests on a remote server, please create additionally a `targets.edn` file. In this file you define gainst which server(s) the tests are performed and the corresponding login information. You may use and adjust the following example config:

```clojure
{:existing [{:node-name "target1"                      ; semantic name (keep the default or use a name that suits you)
             :node-ip "192.168.56.104"}]               ; the ip4 address of the machine to be provisioned
             {:node-name "target2"                     ; semantic name (keep the default or use a name that suits you)
                          :node-ip "192.168.56.105"}]  ; the ip4 address of the machine to be provisioned
 :provisioning-user {:login "initial"                  ; user on the target machine, must have sudo rights
                     :password {:plain "secure1234"}}} ; password can be ommited, if a ssh key is authorized
````

5. **Run the jar** with the following options and inspect the output.
  For installation on localhost:
  ```bash
java -jar dda-hardening-crate-standalone.jar hardening.edn
  ```

  For installation on remote server(s) please specify the targets file:

  ```bash
java -jar dda-hardening-crate-standalone.jar --targets targets.edn hardening.edn
```

## Reference
You will find here the reference for
* target: How targets can be specified
* Domain-Level-API: The high level API with many built-in conventions.
* Infra-Level-API: If the domain conventions don't fit your needs, you can use our low-level API (infra) and easily realize your own conventions.

### Targets
The schema of the domain layer for the targets is:
```clojure
(def ExistingNode
  "Represents a target node with ip and its name."
  {:node-name s/Str   ; semantic name (keep the default or use a name that suits you)
   :node-ip s/Str})   ; the ip4 address of the machine to be provisioned

(def ExistingNodes
  "A sequence of ExistingNodes."
  {s/Keyword [ExistingNode]})

(def ProvisioningUser
  "User used for provisioning."
  {:login s/Str                                ; user on the target machine, must have sudo rights
   (s/optional-key :password) secret/Secret})  ; password can be ommited, if a ssh key is authorized

(def Targets
  "Targets to be used during provisioning."
  {:existing [ExistingNode]                                ; one ore more target nodes.
   (s/optional-key :provisioning-user) ProvisioningUser})  ; user can be ommited to execute on localhost with current user
```
The "targets.edn" file has to match this schema.

### Domain-API
The schema for the hardening is:
```clojure
(def HardeningDomain
  (s/either
    {:webserver                ; block incoming traffic except 22, 80 & 443
          {:additional-incomming-ports [s/Str]}}
    {:all-tier-appserver       ; block incoming traffic except 22, 80 & 443, allow ajp from known ip
        {:additional-incomming-ports [s/Str]
         :allow-ajp-from-ip [s/Str]}}
    {:ssh-only-server          ; block incoming traffic except 22
        {:incomming-ports [s/Str]}}))
```
The "hardening.edn" file has to match this schema.

### Infra-API
The infra configuration is a configuration on the infrastructure level of a crate. It contains the complete configuration options that are possible with the crate functions.

The schema is:
```clojure
(def IpVersion           ; for which ip-versions ip-tables should be applied.
  (s/enum :ipv6 :ipv4))  ; we apply the same rules to both ip-versions

(def IpTables
  {:ip-version (hash-set IpVersion)
   :static-rules (hash-set (s/enum :antilockout-ssh :allow-local :drop-ping
                                   :allow-ftp-as-client :allow-dns-as-client
                                   :allow-established-input :allow-established-output
                                   :log-and-drop-remaining-input :log-and-drop-remaining-output))
   (s/optional-key :allow-ajp-from-ip) [s/Str] ;incoming ip address
   (s/optional-key :incomming-ports) [s/Str]
   (s/optional-key :outgoing-ports) [s/Str]}) ; allow-destination-port)

(def HardeningInfra
 {:settings (hash-set (s/enum :unattende-upgrades
                              :sshd-key-only))
  (s/optional-key :iptables) iptables/IpTables})
```

## Compatability
dda-pallet is compatible to the following versions
* pallet 0.8
* clojure 1.7
* (x)ubunutu14.04 / 16.04

## License
Copyright © 2015, 2016, 2017, 2018 meissa GmbH
Published under [apache2.0 license](LICENSE.md)
