from flask import Flask, redirect, request

import sys
import os
import logging
import time
import json

import iptc

from multiprocessing import Process

from threading import Thread

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

root_dir = os.path.dirname(os.path.realpath(__file__))

flask_www_dir = "%s/www" % root_dir

app = Flask(__name__, static_url_path='/www', static_folder=flask_www_dir)

active_twx_ports = {}

HTTP_OK = 200
HTTP_FAIL = 500

PORT_MAX = 65535

ALLOWED_TWX_PORT_MIN = 3128
ALLOWED_TWX_PORT_MAX = 3148

FLASK_PORT = 5000
FLASK_PORT_STR = "%s" % FLASK_PORT

#TODO: dynamic or else this will impact multiple edge devices
SQUID_PORT_DEFAULT = 3128
SQUID_PORT_DEFAULT_STR = "%s" % SQUID_PORT_DEFAULT

#TWX_PLATFORM_PORT = 8443
#TWX_PLATFORM_PORT_STR = "%s" % TWX_PLATFORM_PORT

FILTER_TABLE_NAME = "filter"

JUDGEMENT_ACCEPT = "ACCEPT"
JUDGEMENT_DROP = "DROP"
JUDGEMENT_REJECT = "REJECT"

INPUT_CHAIN_NAME = "INPUT"
OUTPUT_CHAIN_NAME = "OUTPUT"
FORWARD_CHAIN_NAME = "FORWARD"

DUMMY_STR = "python should make this easier"
STR_CLASS = DUMMY_STR.__class__
DICT_CLASS = {DUMMY_STR : DUMMY_STR}.__class__

logger.info("Starting up...")

logger.info("Using flask www directory: %s" % flask_www_dir)

#####################################

@app.route('/')
def root():
    return redirect("/info")

@app.route('/add_twx_port')
def add_twx_port():
    logger.info("Adding TWX port to caltrops")

    port_arg = request.args.get("port")

    #check if valid port number and in acceptable range
    #add to active ports
    #add accept rule

    #return success on confirmation of rule application

@app.route('/del_twx_port')
def del_twx_port():
    port_arg = request.args.get("port")

    #check if valid port number and in acceptable range
    #add to active ports
    #add accept rule

    #return success on confirmation of rule application

##################
#edge -> TWX, inbound to platform traffic

@app.route('/drop_twx_inbound')
def drop_twx_platform_inbound():

    #>>> rule = {"dst": "172.16.1.1", "protocol": "tcp", "tcp": {"dport": 3128}, "target": {"DNAT": {"to-destination": "100.127.20.21:8080" }}}

    port_arg = request.args.get("port")

    if(port_arg != None):
        if(isValidPort(port_arg)):
            logger.debug("Attempting to add rule to drop traffic to port %s" % port_arg)

            #keep as string
            drop_port = port_arg
        else:
            logger.error("Drop port traffic failed- invalid port")
            return build_rule_change_response(HTTP_FAIL, "{ 'change': 'FAIL' }")
    else:
        #default if no arg is passed
        drop_port = SQUID_PORT_DEFAULT_STR

    logger.debug("Attempting to apply DROP rule for inbound TWX traffic on port %s" % drop_port )

    #inbound dest port?

    if( isTWXPortInboundDrop(drop_port) == True ):
        logger.warning("Skipping adding DROP rule for platform inbound port. Already DROPping")

        #still a successful handling of a request
        return build_rule_change_response(HTTP_OK, "{ 'change': 'SKIP' }")

    input_chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), INPUT_CHAIN_NAME)

    #delete any existing rules for this port

    current_rule = getRuleAffectingPort(drop_port)

    while( current_rule != None ):

        iptc.easy.delete_rule(FILTER_TABLE_NAME, INPUT_CHAIN_NAME, current_rule)

        logger.info("Successfully deleted rule judgement %s for port %s" % (current_rule['target'], drop_port) )

        current_rule = getRuleAffectingPort(drop_port)

    #drop tcp to caltrops on port the squid port 3128, which routes traffic to the twx platform

    rule_drop_squid = iptc.Rule()
    rule_drop_squid.protocol = "tcp"
    match = rule_drop_squid.create_match("tcp")
    match.dport = drop_port #must be string
    rule_drop_squid.target = iptc.Target(rule_drop_squid, JUDGEMENT_DROP)
    input_chain.insert_rule(rule_drop_squid)

    #check our rule change, and report in response
    if(isTWXPortInboundDrop(drop_port)):
        return build_rule_change_response(HTTP_OK, "{ 'change': 'SUCCESS' }")
    else:
        return build_rule_change_response(HTTP_FAIL, "{ 'change': 'FAIL' }")


@app.route('/reject_twx_inbound')
def reject_twx_platform_inbound():

    port_arg = request.args.get("port")

    if(port_arg != None):
        if(isValidPort(port_arg)):
            logger.debug("Attempting to apply rule to reject traffic to port %s" % port_arg)

            #keep as string
            reject_port = port_arg
        else:
            logger.error("Reject port traffic failed- invalid port")
            return build_rule_change_response(HTTP_FAIL, "{ 'change': 'FAIL' }")
    else:
        #default if no arg is passed
        reject_port = SQUID_PORT_DEFAULT_STR

    logger.debug("Attempting to add REJECT rule for inbound TWX traffic on port %s" % reject_port )

    #>>> rule = {"dst": "172.16.1.1", "protocol": "tcp", "tcp": {"dport": 3128}, "target": {"DNAT": {"to-destination": "100.127.20.21:8080" }}}

    #inbound dest port?

    if( isTWXPortInboundReject(reject_port) == True ):
        logger.warning("Skipping adding REJECT rule for platform inbound port. Already REJECTing")

        #still a successful handling of a request
        return build_rule_change_response(HTTP_OK, "{ 'change': 'SKIP' }")

    input_chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), INPUT_CHAIN_NAME)

    #delete any existing rules for this port

    current_rule = getRuleAffectingPort(reject_port)

    while( current_rule != None ):

        logger.debug("Attempting to delete rule: %s" % current_rule)

        iptc.easy.delete_rule(FILTER_TABLE_NAME, INPUT_CHAIN_NAME, current_rule)

        logger.info("Successfully deleted rule judgement %s for port %s" % (current_rule['target'], reject_port) )

        current_rule = getRuleAffectingPort(reject_port)

    #drop tcp to caltrops on port the squid port 3128, which routes traffic to the twx platform

    rule_reject_squid = iptc.Rule()
    rule_reject_squid.protocol = "tcp"
    match = rule_reject_squid.create_match("tcp")
    match.dport = reject_port #must be string
    rule_reject_squid.target = iptc.Target(rule_reject_squid, JUDGEMENT_REJECT)
    input_chain.insert_rule(rule_reject_squid)

    #check our rule change, and report in response
    if(isTWXPortInboundReject(reject_port)):
        return build_rule_change_response(HTTP_OK, "{ 'change': 'SUCCESS' }")
    else:
        return build_rule_change_response(HTTP_FAIL, "{ 'change': 'FAIL' }")

@app.route('/accept_twx_inbound')
def accept_twx_platform_inbound():
    #>>> rule = {"dst": "172.16.1.1", "protocol": "tcp", "tcp": {"dport": 3128}, "target": {"DNAT": {"to-destination": "100.127.20.21:8080" }}}

    #inbound dest port?

    port_arg = request.args.get("port")

    if(port_arg != None):
        if(isValidPort(port_arg)):
            logger.debug("Attempting to add rule to drop traffic to port %s" % port_arg)

            #keep as string
            accept_port = port_arg
        else:
            logger.error("Drop port traffic failed- invalid port")
            return build_rule_change_response(HTTP_FAIL, "{ 'change': 'FAIL' }")
    else:
        #default if no arg is passed
        accept_port = SQUID_PORT_DEFAULT_STR

    logger.debug("Attempting to apply ACCEPT rule for inbound TWX traffic on port %s" % accept_port )

    #check for existing rule
    if(isTWXPortInboundAccept(accept_port)):
        logger.warning("Skipping adding accept rule for platform inbound port. Already ACCEPTing")

        #still a successful handling of a request
        return build_rule_change_response(200, "{ 'change': 'SKIP' }")

    #allow tcp to caltrops on port the squid port 3128, which routes traffic to the twx platform
    input_chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), INPUT_CHAIN_NAME)

    #delete any existing rules for this port
    current_rule = getRuleAffectingPort(accept_port)

    while( current_rule != None ):

        iptc.easy.delete_rule(FILTER_TABLE_NAME, INPUT_CHAIN_NAME, current_rule)

        logger.info("Successfully deleted rule judgement %s for port %s" % (current_rule['target'], accept_port) )

        current_rule = getRuleAffectingPort(accept_port)


    #rule to ACCEPT on the specified port
    rule_allow_squid = iptc.Rule()
    rule_allow_squid.protocol = "tcp"
    match = rule_allow_squid.create_match("tcp")
    match.dport = accept_port #must be string
    rule_allow_squid.target = iptc.Target(rule_allow_squid, JUDGEMENT_ACCEPT)
    input_chain.insert_rule(rule_allow_squid)

    #check our rule change, and report in response
    if(isTWXPortInboundAccept(accept_port)):
        return build_rule_change_response(200, "{ 'change': 'SUCCESS' }")
    else:
        return build_rule_change_response(500, "{ 'change': 'FAIL' }")

##################
#TWX -> edge, outbound from platform traffic

@app.route('/accept_twx_outbound')
def accept_twx_platform_outbound():
    port_arg = request.args.get("port")

    if(port_arg != None):
        if(isValidPort(port_arg)):
            logger.debug("Attempting to add rule to drop traffic from port %s" % port_arg)

            #keep as string
            accept_port = port_arg
        else:
            logger.error("Drop port traffic failed- invalid port")
            return build_rule_change_response(HTTP_FAIL, "{ 'change': 'FAIL' }")
    else:
        #default if no arg is passed
        accept_port = SQUID_PORT_DEFAULT_STR

    logger.debug("Attempting to apply ACCEPT rule for outbound TWX traffic on port %s" % accept_port )

    #check for existing rule
    if(isTWXPortOutboundAccept(accept_port)):
        logger.warning("Skipping adding accept rule for platform outbound port. Already ACCEPTing")

        #still a successful handling of a request
        return build_rule_change_response(200, "{ 'change': 'SKIP' }")

    #allow tcp to caltrops on port the squid port 3128, which routes traffic to the twx platform
    output_chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), OUTPUT_CHAIN_NAME)

    #delete any existing rules for this port
    current_rule = getRuleAffectingPort(accept_port, FILTER_TABLE_NAME, OUTPUT_CHAIN_NAME)

    while( current_rule != None ):

        iptc.easy.delete_rule(FILTER_TABLE_NAME, OUTPUT_CHAIN_NAME, current_rule)

        logger.info("Successfully deleted rule judgement %s for port %s" % (current_rule['target'], accept_port) )

        current_rule = getRuleAffectingPort(accept_port, FILTER_TABLE_NAME, OUTPUT_CHAIN_NAME)


    #rule to ACCEPT on the specified port
    rule_allow_twx_outbound_default = iptc.Rule()
    rule_allow_twx_outbound_default.protocol = "tcp"
    match = rule_allow_twx_outbound_default.create_match("tcp")
    match.sport = accept_port #must be string
    rule_allow_twx_outbound_default.target = iptc.Target(rule_allow_twx_outbound_default, JUDGEMENT_ACCEPT)
    output_chain.insert_rule(rule_allow_twx_outbound_default)

    #check our rule change, and report in response
    if(isTWXPortOutboundAccept(accept_port)):
        return build_rule_change_response(200, "{ 'change': 'SUCCESS' }")
    else:
        return build_rule_change_response(500, "{ 'change': 'FAIL' }")

@app.route('/drop_twx_outbound')
def drop_twx_platform_outbound():

    port_arg = request.args.get("port")

    if(port_arg != None):
        if(isValidPort(port_arg)):
            logger.debug("Attempting to add rule to drop traffic from port %s" % port_arg)

            #keep as string
            drop_port = port_arg
        else:
            logger.error("Drop port traffic failed- invalid port")
            return build_rule_change_response(HTTP_FAIL, "{ 'change': 'FAIL' }")
    else:
        #default if no arg is passed
        drop_port = SQUID_PORT_DEFAULT_STR

    logger.debug("Attempting to apply DROP rule for outbound TWX traffic on port %s" % drop_port )

    #check for existing rule
    if(isTWXPortOutboundDrop(drop_port)):
        logger.warning("Skipping adding DROP rule for platform outbound port. Already DROPping")

        #still a successful handling of a request
        return build_rule_change_response(200, "{ 'change': 'SKIP' }")

    #allow tcp to caltrops on port the squid port 3128, which routes traffic to the twx platform
    output_chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), OUTPUT_CHAIN_NAME)

    #delete any existing rules for this port
    current_rule = getRuleAffectingPort(drop_port, FILTER_TABLE_NAME, OUTPUT_CHAIN_NAME)

    while( current_rule != None ):

        iptc.easy.delete_rule(FILTER_TABLE_NAME, OUTPUT_CHAIN_NAME, current_rule)

        logger.info("Successfully deleted rule judgement %s for port %s" % (current_rule['target'], drop_port) )

        current_rule = getRuleAffectingPort(drop_port, FILTER_TABLE_NAME, OUTPUT_CHAIN_NAME)


    #rule to ACCEPT on the specified port
    rule_drop_twx_outbound_default = iptc.Rule()
    rule_drop_twx_outbound_default.protocol = "tcp"
    match = rule_drop_twx_outbound_default.create_match("tcp")
    match.sport = drop_port #must be string
    rule_drop_twx_outbound_default.target = iptc.Target(rule_drop_twx_outbound_default, JUDGEMENT_DROP)
    output_chain.insert_rule(rule_drop_twx_outbound_default)

    #check our rule change, and report in response
    if(isTWXPortOutboundDrop(drop_port)):
        return build_rule_change_response(200, "{ 'change': 'SUCCESS' }")
    else:
        return build_rule_change_response(500, "{ 'change': 'FAIL' }")

@app.route('/reject_twx_outbound')
def reject_twx_platform_outbound():
    port_arg = request.args.get("port")

    if(port_arg != None):
        if(isValidPort(port_arg)):
            logger.debug("Attempting to add rule to drop traffic from port %s" % port_arg)

            #keep as string
            reject_port = port_arg
        else:
            logger.error("Drop port traffic failed- invalid port")
            return build_rule_change_response(HTTP_FAIL, "{ 'change': 'FAIL' }")
    else:
        #default if no arg is passed
        reject_port = SQUID_PORT_DEFAULT_STR

    logger.debug("Attempting to apply REJECT rule for outbound TWX traffic on port %s" % reject_port )

    #check for existing rule
    if(isTWXPortOutboundReject(reject_port)):
        logger.warning("Skipping adding reject rule for platform outbound port. Already REJECTing")

        #still a successful handling of a request
        return build_rule_change_response(200, "{ 'change': 'SKIP' }")

    #allow tcp to caltrops on port the squid port 3128, which routes traffic to the twx platform
    output_chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), OUTPUT_CHAIN_NAME)

    #delete any existing rules for this port
    current_rule = getRuleAffectingPort(reject_port, FILTER_TABLE_NAME, OUTPUT_CHAIN_NAME)

    while( current_rule != None ):

        iptc.easy.delete_rule(FILTER_TABLE_NAME, OUTPUT_CHAIN_NAME, current_rule)

        logger.info("Successfully deleted rule judgement %s for port %s" % (current_rule['target'], reject_port) )

        current_rule = getRuleAffectingPort(reject_port, FILTER_TABLE_NAME, OUTPUT_CHAIN_NAME)


    #rule to ACCEPT on the specified port
    rule_reject_twx_outbound_default = iptc.Rule()
    rule_reject_twx_outbound_default.protocol = "tcp"
    match = rule_reject_twx_outbound_default.create_match("tcp")
    match.sport = reject_port #must be string
    rule_reject_twx_outbound_default.target = iptc.Target(rule_reject_twx_outbound_default, JUDGEMENT_REJECT)
    output_chain.insert_rule(rule_reject_twx_outbound_default)

    #check our rule change, and report in response
    if(isTWXPortOutboundReject(reject_port)):
        return build_rule_change_response(200, "{ 'change': 'SUCCESS' }")
    else:
        return build_rule_change_response(500, "{ 'change': 'FAIL' }")

@app.route("/reset_rules")
def reset_rules():
    #remove any non-accepting rules affecting squid inbound

    #remove any non-accepting rules affecting outbound

    #set squid ports to accept
    accept_twx_platform_inbound()

    #need to keep the flask port open though


    #check our rule change, and report in response
    if(isTWXPortInboundAccept()):
        return build_rule_change_response(200, "{ 'change': 'SUCCESS' }")
    else:
        return build_rule_change_response(500, "{ 'change': 'FAIL' }")


@app.route('/shutdown')
def caltrops_shutdown():
    pass

@app.route('/info')
def home():

    logger.info("Displaying iptables info")

    #TODO: favicon

    output = "<html><head></head><body>\n"

    #TODO: logo on page

    #to test, add a rule with iptables-legacy: /usr/sbin/iptables-legacy -A INPUT -p tcp -m tcp --dport 24800 -j ACCEPT
    logger.debug("filter easy.dump_table: %s" % iptc.easy.dump_table(FILTER_TABLE_NAME))

    output = "%s\n<br>\nInput Chain\n" % output

    for rule in iptc.easy.dump_chain(FILTER_TABLE_NAME, INPUT_CHAIN_NAME):
        output = "%s<br>%s\n" % (output, rule)

    output = "%s<hr>\n" % output

    output = "%s\n<br>\nOutput Chain\n" % output

    for rule in iptc.easy.dump_chain(FILTER_TABLE_NAME, OUTPUT_CHAIN_NAME):
        output = "%s<br>%s\n" % (output, rule)

    output = "%s<hr>\n" % output

    output = "%s\n<br>\nForward Chain" % output

    for rule in iptc.easy.dump_chain(FILTER_TABLE_NAME, FORWARD_CHAIN_NAME):
        output = "%s<br>%s\n" % (output, rule)

    output = "\n%s<hr>\n" % output

    return ("\n%s</body></html>" % output)

# @app.route('/stop')
# def stop():
#     logger.info("Shutting down...")
#
#     global server
#     server.terminate()
#
#     return "Shutting down"

##############################
#flask seems to require this here, after the endpoints are defined above

def isValidPort(port_str):
    port_num = int(port_str)
    return (
        port_num > 0 and
        port_num < PORT_MAX and
        (port_num >= ALLOWED_TWX_PORT_MIN and port_num <= ALLOWED_TWX_PORT_MIN) and
        port_num != FLASK_PORT)

def build_rule_change_response(status_code, data={}):
    return app.response_class(
        response=json.dumps(data, sort_keys=True),
        status=status_code,
        mimetype='application/json'
    )


#check if any rule at all exists affecting a specified port
#returns a rule if one if found, None if no rule is found
def getRuleAffectingPort(port_str, table=FILTER_TABLE_NAME, chain=INPUT_CHAIN_NAME):
    result = None

    #TODO: enforce port is string

    #this function checks edge to platform on dport, platform to edge on sport
    port_field = "dport"
    if(chain == OUTPUT_CHAIN_NAME):
        port_field = "sport"

    for rule in iptc.easy.dump_chain(table, chain):
        if(rule['tcp'][port_field] == port_str ):
            result = rule
            break

    if(result == None):
        logger.info("Could not find any rule in %s.%s affecting port %s" % (table, chain, port_str) )
    else:
        logger.info("Found a rule in %s.%s affecting port %s: %s" % (table, chain, port_str, result) )

    return result

#first rule found affecting port wins
#returns true or false if the table.chain currently has a rule for the port with specified target
def checkPortHasTarget(port_str, table=FILTER_TABLE_NAME, chain=INPUT_CHAIN_NAME, target=JUDGEMENT_ACCEPT):

    retval = False

    #TODO: enforce port is string

    current_rule = getRuleAffectingPort(port_str, table, chain)

    if(current_rule == None):
        if(target == JUDGEMENT_ACCEPT):
            #by default, no rule existing is assumed to accept
            retval = True
        else:
            retval = False
    else:
        #rule target is a 1-level dict
        #the target key seems to resolve a string of ACCEPT/DROP, or a string describing REJECT: {'REJECT': {'reject-with': 'icmp-port-unreachable'}}
        current_rule_target = current_rule.get('target')

        logger.info("current_rule_target is of type %s" % type(current_rule_target) )

        if( (target == JUDGEMENT_ACCEPT or target == JUDGEMENT_DROP) ):
            if(target == current_rule_target):
                #'target': 'ACCEPT'
                #'target': 'DROP'

                logger.debug("checkPortHasTarget found port %s already has target: %s" % (port_str, target) )
                retval = True

        elif(target == JUDGEMENT_REJECT):

            #special case as reject can have a subjudgment as a string or dict
            #'target': {'REJECT': {'reject-with': 'icmp-port-unreachable'}}

            if( type(current_rule_target) == STR_CLASS):
                if(current_rule_target == "{'REJECT': {'reject-with': 'icmp-port-unreachable'}}"):
                    logger.debug("checkPortHasTarget string-match found port %s has reject target: %s" % (port_str, target) )
                    retval = True
            elif( type(current_rule_target) == DICT_CLASS):
                if(current_rule_target.get("REJECT", None) != None ):
                    logger.debug("checkPortHasTarget dict-match found port %s has reject target: %s" % (port_str, target) )
                    retval = True

        else:
            logger.debug("checkPortHasTarget found port %s DOES NOT have target: %s" % (port_str, current_rule_target) )
            retval = False

    return retval

def isTWXPortInboundAccept(port_str):
    #edge -> platform

    return checkPortHasTarget(port_str, FILTER_TABLE_NAME, INPUT_CHAIN_NAME, JUDGEMENT_ACCEPT )

def isTWXPortInboundReject(port_str):
    #edge -> platform

    return checkPortHasTarget(port_str, FILTER_TABLE_NAME, INPUT_CHAIN_NAME, JUDGEMENT_REJECT )

def isTWXPortInboundDrop(port_str):
    #edge -> platform

    return checkPortHasTarget(port_str, FILTER_TABLE_NAME, INPUT_CHAIN_NAME, JUDGEMENT_DROP )

def isTWXPortOutboundAccept(port_str):
    # platform => edge

    return checkPortHasTarget(port_str, FILTER_TABLE_NAME, OUTPUT_CHAIN_NAME, JUDGEMENT_ACCEPT )

def isTWXPortOutboundReject(port_str):
    # platform => edge

    return checkPortHasTarget(port_str, FILTER_TABLE_NAME, OUTPUT_CHAIN_NAME, JUDGEMENT_REJECT )

def isTWXPortOutboundDrop(port_str):
    # platform => edge

    return checkPortHasTarget(port_str, FILTER_TABLE_NAME, OUTPUT_CHAIN_NAME, JUDGEMENT_DROP )

def startup():
    #add the basic routing and perform any setup
    #after execution, source should be able to destination through container as an open proxy

    logger.info("Starting up caltrops")

    #expect the platform to run on this same host, but outside this container
    #won't be able to block platform ports

    #default iptables rules
    #docker networking needs to be set up accordingly

    input_chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), INPUT_CHAIN_NAME)
    output_chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), OUTPUT_CHAIN_NAME)

    #problematic, affects the accept rules
    #input_chain.set_policy(JUDGEMENT_DROP)
    #output_chain.set_policy(JUDGEMENT_DROP)

    #allow tcp to caltrops on port 4444
    logger.info("Inserting default caltrops inbound rule")
    rule_allow_flask = iptc.Rule()
    rule_allow_flask.protocol = "tcp"
    match = rule_allow_flask.create_match("tcp")
    match.dport = FLASK_PORT_STR #must be string
    rule_allow_flask.target = iptc.Target(rule_allow_flask, "ACCEPT")
    input_chain.insert_rule(rule_allow_flask)

    #allow tcp to squid running on the twx default port 3128
    #TODO: maybe skip this and expect rest calls to set up
    logger.info("Inserting default twx inbound rule")
    rule_allow_twx_inbound_default = iptc.Rule()
    rule_allow_twx_inbound_default.protocol = "tcp"
    match = rule_allow_twx_inbound_default.create_match("tcp")
    match.dport = SQUID_PORT_DEFAULT_STR #must be string
    rule_allow_twx_inbound_default.target = iptc.Target(rule_allow_twx_inbound_default, "ACCEPT")
    input_chain.insert_rule(rule_allow_twx_inbound_default)

    #allow outbound traffic on twx default port 3128
    logger.info("Inserting default twx outbound rule")
    rule_allow_twx_outbound_default = iptc.Rule()
    rule_allow_twx_outbound_default.protocol = "tcp"
    match = rule_allow_twx_outbound_default.create_match("tcp")
    match.sport = SQUID_PORT_DEFAULT_STR #must be string
    rule_allow_twx_outbound_default.target = iptc.Target(rule_allow_twx_outbound_default, "ACCEPT")
    output_chain.insert_rule(rule_allow_twx_outbound_default)

    #TODO: set default policy on INPUT and OUTPUT to drop
    #iptc.easy.set_policy
    #can only be ACCEPT or DROP on built-in chains
    #problematic, causes accept rules to be dropped
    #input_chain.set_policy(JUDGEMENT_DROP)
    #output_chain.set_policy(JUDGEMENT_DROP)

    rules_str = ""

    for rule in iptc.easy.dump_chain(FILTER_TABLE_NAME, INPUT_CHAIN_NAME):
        #this_rule = "proto: %s, target: %s" % (rule.protocol, rule.target._get_target())
        rules_str = "%s\n%s" % (rules_str, rule)

    for rule in iptc.easy.dump_chain(FILTER_TABLE_NAME, OUTPUT_CHAIN_NAME):
        #this_rule = "proto: %s, target: %s" % (rule.protocol, rule.target._get_target())
        rules_str = "%s\n%s" % (rules_str, rule)

    #sanity check squid port has accept judgement
    if(isTWXPortInboundAccept(SQUID_PORT_DEFAULT_STR) == True):
        logger.info("isTWXPortInboundAccept reports platform port has accept judgement")
    else:
        logger.error("isTWXPortInboundAccept reports platform port does not have accept judgement")

    if(isTWXPortOutboundAccept(SQUID_PORT_DEFAULT_STR) == True):
        logger.info("isTWXPortOutboundAccept reports platform port has accept judgement")
    else:
        logger.error("isTWXPortOutboundAccept reports platform port does not have accept judgement")

    if(checkPortHasTarget(FLASK_PORT_STR) == True):
        logger.info("checkPortHasTarget reports flask port has accept judgement")
    else:
        logger.error("checkPortHasTarget reports flask port does not have accept judgement")

    #print all rules
    logger.info("Startup completed. Current rules:\n %s" %  rules_str)



def shutdown():
    #drop all of caltrops rules on relevant chains, likely input, output and forward
    logger.info("Shutting down caltrops")



    pass




if __name__ == '__main__':

    #TODO: config directives
    server = Process(target=app.run, args=('0.0.0.0', FLASK_PORT))

    startup()

    #######################
    #for debug - quit after a set time period
    def quitfn():
        logger.info("Quit thread started")
        time.sleep(200)

        shutdown()

        logger.info("Exiting...")
        server.terminate()

    #launch our quit thread
    #for debugging and quick testing
    #t = Thread(target=quitfn, daemon=True)
    #t.start()
    #######################

    #run flask app
    server.start()