## caltrops
Caltrops is an application for simulating connectivity failures in a controlled manner- by allowing external management of iptables rules around proxy connections between software client/edge and server/platform.

The Caltrops application runs in a container alongside instances of the [Squid proxy server](https://www.squid-cache.org), and legacy iptables. The container is available on DockerHub at https://hub.docker.com/r/jas0ndiamond/caltrops. Web endpoints are exposed using [flask](https://flask.palletsprojects.com/) to allow iptables rules to be managed via requested issued from a command-line application like `curl` or `wget`, or with your REST library of choice, and test how your client/edge and/or server/platform reacts to varieties of connectivity loss.

By default, 20 ports (3128 through 3148, inclusive) are served by the squid instance for client connections. The intention is that one application connection policy should be used per proxy port on caltrops. An implication of this is that the iptables rule ordering should not affect connectivity for a client/edge application.

The client/edge device must support proxy connections with basic authentication.

Developed for testing IoT connectivity- specifically when operating virtual ThingWorx IoT Edge aircraft in project [thingworx-flightgear-edge](https://github.com/jas0ndiamond/thingworx-flightgear-edge)

## Outline
![caltrops](https://user-images.githubusercontent.com/7103526/194747935-c3bf107c-7836-45c1-b3c9-76b77639d2d4.png)

## Components
* Python3
* flask
* iptables
* squid
* docker

## Getting Started
Caltrops can run standalone as a python application, but is intended to run in a docker container.

### Installation

Retrieve the container from docker hub:
```bash
docker pull jas0ndiamond/caltrops
```

### Quickstart

Start Caltrops by executing:
```bash
docker run --name jas0ndiamond/caltrops --privileged=true -p 5000:5000
```

If Caltrops expects to handle external traffic, the proxy ports must also be published when running the container:
```bash
docker pull jas0ndiamond/caltrops
docker run --name jas0ndiamond/caltrops --privileged=true -p 5000:5000 -p 3128-3148:3128-3148
```

The Caltrops UI is available at http://caltrops_host:5000, which will display a simple readout of the iptables rules in place.

Connect your device to the proxy port. The default target for the proxy ports is ACCEPT, so a connection attempt should succeed. The proxy is configured by default with Basic auth in the Dockerfile, with user `myproxyuser`, and password `myproxypass`

Connections through caltrops can also be tested with curl:
```bash
curl -i --proxy "http://myproxyuser:myproxypass@caltrops_host:3128"  "https://www.github.com"
```

### Affecting traffic

Affect the traffic judgments of the ports by issuing the following REST requests.

For inbound traffic, specifically traffic originating from the client to Caltrops, use the following endpoints:
* accept_inbound (http://caltrops_host:5000/accept_inbound?port=myport)
* drop_inbound (http://caltrops_host:5000/drop_inbound?port=myport)
* reject_inbound (http://caltrops_host:5000/reject_inbound?port=myport)

For example, to DROP traffic inbound from the client connected to caltrops on port 3131, the relevant rule can be set either with the following `curl` command, or with your REST library of choice:
```bash
curl -i "http://caltrops_host:5000/drop_inbound?port=3131"
```

An HTTP 200 will be returned on success, with field `change` set accordingly:
* `SUCCESS` - the rule changed was successfully applied
* `SKIP` - the rule was successfully determined to not need changing (i.e. attempting to apply an ACCEPT target to a rule already with an ACCEPT target)
* `FAIL` - the rule change failed, likely due to an invalid/malformed port, or a port not served by the underlying squid instance.

An HTTP 500 will be returned on an internal failure. Please report instances of this.

---

For outbound traffic, specifically traffic originating from the server to Caltrops, use the following endpoints:
* accept_outbound (http://caltrops_host:5000/accept_outbound?port=myport)
* drop_outbound (http://caltrops_host:5000/drop_outbound?port=myport)
* reject_outbound (http://caltrops_host:5000/reject_outbound?port=myport)

For example, to REJECT traffic inbound from the client connected to caltrops on port 3131, the relevant rule can be set either with the following `curl` command, or with your REST library of choice:
```bash
curl -i "http://caltrops_host:5000/reject_outbound?port=3131"
```

An HTTP 200 will be returned on success, with field `change` set accordingly:
* `SUCCESS` - the rule changed was successfully applied
* `SKIP` - the rule was successfully determined to not need changing (i.e. attempting to apply an ACCEPT target to a rule already with an ACCEPT target)
* `FAIL` - the rule change failed, likely due to an invalid/malformed port, or a port not served by the underlying squid instance.

An HTTP 500 will be returned on an internal failure. Please report instances of this.

---

Rules can be reset to the startup default by issuing a request to `http://caltrops_host:5000/reset_rules`

---

The default proxy ports can be changed by modifying the container's squid config file, and the caltrops.py python application. Ensure that the new port range is published when the container is run.

## Testing

Basic tests can be executed from the project root directory by running:
```bash
#ensure your caltrops container is running first!
python3 -m unittest test/caltrops_test.py
```

## TODO
* Rate-limiting iptables rules.
* Probability-based packet loss rules.
* Optional persistence of rules.
