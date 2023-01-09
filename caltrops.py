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

HR_HTML = "<hr style=\"background-color:#666666;border-radius: 7px 7px 7px 7px;height: 6px;width:900px\">"


HTTP_OK = 200
HTTP_FAIL = 500

#ensure this port range does contain the flask port
ALLOWED_PROXY_PORT_MIN = 13128
ALLOWED_PROXY_PORT_MAX = 13148

#ensure this port does not conflict with the proxy port range
FLASK_PORT = 15000
FLASK_PORT_STR = "%s" % FLASK_PORT

#TODO: dynamic or else this will impact multiple edge devices
SQUID_PORT_DEFAULT = ALLOWED_PROXY_PORT_MIN
SQUID_PORT_DEFAULT_STR = "%s" % SQUID_PORT_DEFAULT

FILTER_TABLE_NAME = "filter"

JUDGEMENT_ACCEPT = "ACCEPT"
JUDGEMENT_DROP = "DROP"
JUDGEMENT_REJECT = "REJECT"

INPUT_CHAIN_NAME = "INPUT"
OUTPUT_CHAIN_NAME = "OUTPUT"
FORWARD_CHAIN_NAME = "FORWARD"

PORT_PARAM_NAME = "port"

CHANGE_RESP_FIELD = "change"
CHANGE_FAIL_VAL = "FAIL"
CHANGE_SUCCESS_VAL = "SUCCESS"
CHANGE_SKIP_VAL = "SKIP"


DUMMY_STR = "python should make this easier"
STR_CLASS = DUMMY_STR.__class__
DICT_CLASS = {DUMMY_STR : DUMMY_STR}.__class__

logger.info("Launching caltrops...")

logger.info("Using flask www directory: %s" % flask_www_dir)

#####################################

@app.route('/', methods=['GET'])
def root():
    return redirect("/info")

##################
#edge -> platform, inbound to platform traffic

@app.route('/drop_inbound', methods=['GET'])
def drop_inbound():

    #>>> rule = {"dst": "172.16.1.1", "protocol": "tcp", "tcp": {"dport": 13128}, "target": {"DNAT": {"to-destination": "100.127.20.21:8080" }}}

    port_arg = request.args.get(PORT_PARAM_NAME)[:5]

    if(port_arg != None):
        if(isValidPort(port_arg)):
            logger.debug("Attempting to add rule to drop traffic to port %s" % port_arg)

            #keep as string
            drop_port = port_arg
        else:
            logger.error("Drop port traffic failed- invalid port")
            return build_rule_change_response_from_str(HTTP_FAIL, CHANGE_FAIL_VAL)
    else:
        #default if no arg is passed
        drop_port = SQUID_PORT_DEFAULT_STR

    logger.debug("Attempting to apply DROP rule for inbound traffic on port %s" % drop_port )

    #inbound dest port?

    if( isInboundDropRuleActive(drop_port) == True ):
        logger.warning("Skipping adding DROP rule for platform inbound port. Already DROPping")

        #still a successful handling of a request
        return build_rule_change_response_from_str(HTTP_OK, CHANGE_SKIP_VAL)

    #delete any existing rules for this port

    current_rule = getRuleAffectingPort(drop_port)

    while( current_rule != None ):

        iptablesDeleteRuleInbound(current_rule)

        logger.info("Successfully deleted rule judgement %s for port %s" % (current_rule['target'], drop_port) )

        current_rule = getRuleAffectingPort(drop_port)

    #drop tcp to caltrops on port the squid port, which routes traffic to the platform

    iptablesInsertRuleInbound(drop_port, JUDGEMENT_DROP)

    #check our rule change, and report in response
    if(isInboundDropRuleActive(drop_port)):
        return build_rule_change_response_from_str(HTTP_OK, CHANGE_SUCCESS_VAL)
    else:
        return build_rule_change_response_from_str(HTTP_FAIL, CHANGE_FAIL_VAL)


@app.route('/reject_inbound', methods=['GET'])
def reject_inbound():

    port_arg = request.args.get(PORT_PARAM_NAME)[:5]

    if(port_arg != None):
        if(isValidPort(port_arg)):
            logger.debug("Attempting to apply rule to reject traffic to port %s" % port_arg)

            #keep as string
            reject_port = port_arg
        else:
            logger.error("Reject port traffic failed- invalid port")
            return build_rule_change_response_from_str(HTTP_FAIL, CHANGE_FAIL_VAL)
    else:
        #default if no arg is passed
        reject_port = SQUID_PORT_DEFAULT_STR

    logger.debug("Attempting to add REJECT rule for inbound traffic on port %s" % reject_port )

    #>>> rule = {"dst": "172.16.1.1", "protocol": "tcp", "tcp": {"dport": 13128}, "target": {"DNAT": {"to-destination": "100.127.20.21:8080" }}}

    if( isInboundRejectRuleActive(reject_port) == True ):
        logger.warning("Skipping adding REJECT rule for platform inbound port. Already REJECTing")

        #still a successful handling of a request
        return build_rule_change_response_from_str(HTTP_OK, CHANGE_SKIP_VAL)

    #delete any existing rules for this port

    current_rule = getRuleAffectingPort(reject_port)

    while( current_rule != None ):

        iptablesDeleteRuleInbound(current_rule)

        logger.info("Successfully deleted rule judgement %s for port %s" % (current_rule['target'], reject_port) )

        current_rule = getRuleAffectingPort(reject_port)

    #drop tcp to caltrops on port the squid port 13128, which routes traffic to the platform

    iptablesInsertRuleInbound(reject_port, JUDGEMENT_REJECT)

    #check our rule change, and report in response
    if(isInboundRejectRuleActive(reject_port)):
        return build_rule_change_response_from_str(HTTP_OK, CHANGE_SUCCESS_VAL)
    else:
        return build_rule_change_response_from_str(HTTP_FAIL, CHANGE_FAIL_VAL)

@app.route('/accept_inbound', methods=['GET'])
def accept_inbound():
    #>>> rule = {"dst": "172.16.1.1", "protocol": "tcp", "tcp": {"dport": 13128}, "target": {"DNAT": {"to-destination": "100.127.20.21:8080" }}}

    #inbound dest port?

    port_arg = request.args.get(PORT_PARAM_NAME)[:5]

    if(port_arg != None):
        if(isValidPort(port_arg)):
            logger.debug("Attempting to add rule to drop traffic to port %s" % port_arg)

            #keep as string
            accept_port = port_arg
        else:
            logger.error("Drop port traffic failed- invalid port")
            return build_rule_change_response_from_str(HTTP_FAIL, CHANGE_FAIL_VAL)
    else:
        #default if no arg is passed
        accept_port = SQUID_PORT_DEFAULT_STR

    logger.debug("Attempting to apply ACCEPT rule for inbound traffic on port %s" % accept_port )

    #check for existing rule
    if(isInboundAcceptRuleActive(accept_port)):
        logger.warning("Skipping adding accept rule for platform inbound port. Already ACCEPTing")

        #still a successful handling of a request
        return build_rule_change_response_from_str(HTTP_OK, CHANGE_SKIP_VAL)

    #allow tcp to caltrops on port the squid port 13128, which routes traffic to the platform

    #delete any existing rules for this port
    current_rule = getRuleAffectingPort(accept_port)

    while( current_rule != None ):

        iptablesDeleteRuleInbound(current_rule)

        logger.info("Successfully deleted rule judgement %s for port %s" % (current_rule['target'], accept_port) )

        current_rule = getRuleAffectingPort(accept_port)

    iptablesInsertRuleInbound(accept_port, JUDGEMENT_ACCEPT)

    #check our rule change, and report in response
    if(isInboundAcceptRuleActive(accept_port)):
        return build_rule_change_response_from_str(HTTP_OK, CHANGE_SUCCESS_VAL)
    else:
        return build_rule_change_response_from_str(HTTP_FAIL, CHANGE_FAIL_VAL)

##################
#platform -> edge, outbound from platform traffic

@app.route('/accept_outbound', methods=['GET'])
def accept_outbound():
    port_arg = request.args.get(PORT_PARAM_NAME)[:5]

    if(port_arg != None):
        if(isValidPort(port_arg)):
            logger.debug("Attempting to add rule to drop traffic from port %s" % port_arg)

            #keep as string
            accept_port = port_arg
        else:
            logger.error("Drop port traffic failed- invalid port")
            return build_rule_change_response_from_str(HTTP_FAIL, CHANGE_FAIL_VAL)
    else:
        #default if no arg is passed
        accept_port = SQUID_PORT_DEFAULT_STR

    logger.debug("Attempting to apply ACCEPT rule for outbound traffic on port %s" % accept_port )

    #check for existing rule
    if(isOutboundAcceptRuleActive(accept_port)):
        logger.warning("Skipping adding accept rule for platform outbound port. Already ACCEPTing")

        #still a successful handling of a request
        return build_rule_change_response_from_str(HTTP_OK, CHANGE_SKIP_VAL)

    #allow tcp to caltrops on port the squid port 13128, which routes traffic to the platform

    #delete any existing rules for this port
    current_rule = getRuleAffectingPort(accept_port, FILTER_TABLE_NAME, OUTPUT_CHAIN_NAME)

    while( current_rule != None ):

        iptablesDeleteRuleOutbound(current_rule)

        logger.info("Successfully deleted rule judgement %s for port %s" % (current_rule['target'], accept_port) )

        current_rule = getRuleAffectingPort(accept_port, FILTER_TABLE_NAME, OUTPUT_CHAIN_NAME)

    iptablesInsertRuleOutbound(accept_port, JUDGEMENT_ACCEPT)

    #check our rule change, and report in response
    if(isOutboundAcceptRuleActive(accept_port)):
        return build_rule_change_response_from_str(HTTP_OK, CHANGE_SUCCESS_VAL)
    else:
        return build_rule_change_response_from_str(HTTP_FAIL, CHANGE_FAIL_VAL)

@app.route('/drop_outbound', methods=['GET'])
def drop_outbound():

    port_arg = request.args.get(PORT_PARAM_NAME)[:5]

    if(port_arg != None):
        if(isValidPort(port_arg)):
            logger.debug("Attempting to add rule to drop traffic from port %s" % port_arg)

            #keep as string
            drop_port = port_arg
        else:
            logger.error("Drop port traffic failed- invalid port")
            return build_rule_change_response_from_str(HTTP_FAIL, CHANGE_FAIL_VAL)
    else:
        #default if no arg is passed
        drop_port = SQUID_PORT_DEFAULT_STR

    logger.debug("Attempting to apply DROP rule for outbound traffic on port %s" % drop_port )

    #check for existing rule
    if(isOutboundDropRuleActive(drop_port)):
        logger.warning("Skipping adding DROP rule for platform outbound port. Already DROPping")

        #still a successful handling of a request
        return build_rule_change_response_from_str(HTTP_OK, CHANGE_SKIP_VAL)

    #allow tcp to caltrops on port the squid port 13128, which routes traffic to the platform

    #delete any existing rules for this port
    current_rule = getRuleAffectingPort(drop_port, FILTER_TABLE_NAME, OUTPUT_CHAIN_NAME)

    while( current_rule != None ):

        iptablesDeleteRuleOutbound(current_rule)

        logger.info("Successfully deleted rule judgement %s for port %s" % (current_rule['target'], drop_port) )

        current_rule = getRuleAffectingPort(drop_port, FILTER_TABLE_NAME, OUTPUT_CHAIN_NAME)


    iptablesInsertRuleOutbound(drop_port, JUDGEMENT_DROP)

    #check our rule change, and report in response
    if(isOutboundDropRuleActive(drop_port)):
        return build_rule_change_response_from_str(HTTP_OK, CHANGE_SUCCESS_VAL)
    else:
        return build_rule_change_response_from_str(HTTP_FAIL, CHANGE_FAIL_VAL)

@app.route('/reject_outbound', methods=['GET'])
def reject_outbound():
    port_arg = request.args.get(PORT_PARAM_NAME)[:5]

    if(port_arg != None):
        if(isValidPort(port_arg)):
            logger.debug("Attempting to add rule to drop traffic from port %s" % port_arg)

            #keep as string
            reject_port = port_arg
        else:
            logger.error("Drop port traffic failed- invalid port")
            return build_rule_change_response_from_str(HTTP_FAIL, CHANGE_FAIL_VAL)
    else:
        #default if no arg is passed
        reject_port = SQUID_PORT_DEFAULT_STR

    logger.debug("Attempting to apply REJECT rule for outbound traffic on port %s" % reject_port )

    #check for existing rule
    if(isOutboundRejectRuleActive(reject_port)):
        logger.warning("Skipping adding reject rule for platform outbound port. Already REJECTing")

        #still a successful handling of a request
        return build_rule_change_response_from_str(HTTP_OK, CHANGE_SKIP_VAL)

    #allow tcp to caltrops on port the squid port 13128, which routes traffic to the platform

    #delete any existing rules for this port
    current_rule = getRuleAffectingPort(reject_port, FILTER_TABLE_NAME, OUTPUT_CHAIN_NAME)

    while( current_rule != None ):

        iptablesDeleteRuleOutbound(current_rule)

        logger.info("Successfully deleted rule judgement %s for port %s" % (current_rule['target'], reject_port) )

        current_rule = getRuleAffectingPort(reject_port, FILTER_TABLE_NAME, OUTPUT_CHAIN_NAME)

    iptablesInsertRuleOutbound(reject_port, JUDGEMENT_REJECT)

    #check our rule change, and report in response
    if(isOutboundRejectRuleActive(reject_port)):
        return build_rule_change_response_from_str(HTTP_OK, CHANGE_SUCCESS_VAL)
    else:
        return build_rule_change_response_from_str(HTTP_FAIL, CHANGE_FAIL_VAL)

@app.route("/get_rules", methods=['GET'])
def get_rules():

    #no sorting, order matters

    #FILTER_TABLE_NAME
    ##INPUT
    ###rule 1
    ###rule 2
    ###rule 3
    ##OUTPUT
    ###rule 1
    ###rule 2
    ###rule 3
    ##FORWARD
    #...


    #rule_data = iptc.easy.dump_table(FILTER_TABLE_NAME)
    rule_data = {}
    rule_data.update( { FILTER_TABLE_NAME : {INPUT_CHAIN_NAME : [], OUTPUT_CHAIN_NAME : [], FORWARD_CHAIN_NAME : [] } } )

    for rule in iptc.easy.dump_chain(FILTER_TABLE_NAME, INPUT_CHAIN_NAME):
        rule_str = ("%s" % rule)

        rule_data.get(FILTER_TABLE_NAME).get(INPUT_CHAIN_NAME).append( rule_str )

    for rule in iptc.easy.dump_chain(FILTER_TABLE_NAME, OUTPUT_CHAIN_NAME):
        rule_str = "%s" % rule

        rule_data.get(FILTER_TABLE_NAME).get(OUTPUT_CHAIN_NAME).append( rule_str )

    for rule in iptc.easy.dump_chain(FILTER_TABLE_NAME, FORWARD_CHAIN_NAME):
        rule_str = "%s" % rule

        rule_data.get(FILTER_TABLE_NAME).get(FORWARD_CHAIN_NAME).append( rule_str )

    return app.response_class(
        response=json.dumps(rule_data, sort_keys=True),
        status=HTTP_OK,
        mimetype='application/json'
    )

@app.route('/reset_rules', methods=['GET'])
def reset_rules():

    logger.info("Resetting iptables rules")

    flushRules()

    if(setDefaultRules() == True):
        return build_rule_change_response_from_str(HTTP_OK, CHANGE_SUCCESS_VAL)
    else:
        return build_rule_change_response_from_str(HTTP_FAIL, CHANGE_FAIL_VAL)

@app.route('/info', methods=['GET'])
def home():

    logger.info("Displaying iptables info")

    output = """<html>\n
    <head>\n
    <title>caltrops</title>\n
    <link rel="icon" type="image/x-icon" href="/www/favicon.ico">
    </head>\n

    """

    #TODO: sort lists of rules -> no we should not obscure the rule order
    #TODO: basic control interface
    #TODO: dynamic diagram

    #to test, add a rule with iptables-legacy: /usr/sbin/iptables-legacy -A INPUT -p tcp -m tcp --dport 24800 -j ACCEPT
    logger.debug("filter easy.dump_table: %s" % iptc.easy.dump_table(FILTER_TABLE_NAME))

    output = "%s\n<h2>Caltrops</h2>\n" % (output)

    output = "%s\n<hr style=\"background-color:#666666;border-radius: 7px 7px 7px 7px;height: 6px;width:1200px;margin-left:0\">\n" % (output)

    output = "%s\n<table width=\"1200\"><tr><td align=\"left\" style=\"background-color:#d9d9d9;\ width=\"900\">\n" % output

    output = "%s\n<h3>Input Chain</h3>\n" % output

    for rule in iptc.easy.dump_chain(FILTER_TABLE_NAME, INPUT_CHAIN_NAME):
        output = "%s\n%s\n<br>\n" % (output, rule)

    output = "%s\n%s\n" % (output, HR_HTML)

    output = "%s\n<h3>Output Chain</h3>\n" % output

    for rule in iptc.easy.dump_chain(FILTER_TABLE_NAME, OUTPUT_CHAIN_NAME):
        output = "%s\n%s\n<br>\n" % (output, rule)

    output = "%s\n%s\n" % (output, HR_HTML)

    output = "%s\n<h3>Forward Chain</h3>" % output

    for rule in (iptc.easy.dump_chain(FILTER_TABLE_NAME, FORWARD_CHAIN_NAME)):
        output = "%s\n%s\n<br>\n" % (output, rule)

    output = "%s\n%s\n" % (output, HR_HTML)

    output = "%s</td>\n<td style=\"background-color:#ffffff;\ align=\"left\" valign=\"top\"><img src=\"/www/caltrops_logo.png\"></td>\n</tr>\n</table>\n" % output

    return ("%s</body></html>" % output)

##############################
#flask seems to require this here, after the endpoints are defined above

#insert a rule affecting inbound traffic. filter on destination port
def iptablesInsertRuleInbound(port=SQUID_PORT_DEFAULT_STR, judgement=JUDGEMENT_ACCEPT):

    input_chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), INPUT_CHAIN_NAME)

    new_rule = iptc.Rule()
    new_rule.protocol = "tcp"
    match = new_rule.create_match("tcp")
    match.dport = port #must be string
    new_rule.target = iptc.Target(new_rule, judgement)
    input_chain.insert_rule(new_rule)

#insert a rule affecting outbound traffic. filter on source port
def iptablesInsertRuleOutbound(port=SQUID_PORT_DEFAULT_STR, judgement=JUDGEMENT_ACCEPT):

    output_chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), OUTPUT_CHAIN_NAME)

    new_rule = iptc.Rule()
    new_rule.protocol = "tcp"
    match = new_rule.create_match("tcp")
    match.sport = port #must be string
    new_rule.target = iptc.Target(new_rule, judgement)
    output_chain.insert_rule(new_rule)

def iptablesDeleteRuleInbound(rule):
    #rule is a iptc rule object returned from getRuleAffectingPort

    if(rule != None):
        iptc.easy.delete_rule(FILTER_TABLE_NAME, INPUT_CHAIN_NAME, rule)

    else:
        logger.warn("Failed to resolve inbound rule to delete")


def iptablesDeleteRuleOutbound(rule):
    #rule is a iptc rule object returned from getRuleAffectingPort

    if(rule != None):
        iptc.easy.delete_rule(FILTER_TABLE_NAME, OUTPUT_CHAIN_NAME, rule)
    else:
        logger.warn("Failed to resolve outbound rule to delete")

def isValidPort(port_str):
    port_num = int(port_str)
    return (
        (port_num >= ALLOWED_PROXY_PORT_MIN and port_num <= ALLOWED_PROXY_PORT_MAX) and
        port_num != FLASK_PORT)

def build_rule_change_response_from_str(status_code, result):

    json_result = {}
    json_result[CHANGE_RESP_FIELD] = result

    return build_rule_change_response(status_code, json_result)

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

def isInboundAcceptRuleActive(port_str):
    #edge -> platform

    return checkPortHasTarget(port_str, FILTER_TABLE_NAME, INPUT_CHAIN_NAME, JUDGEMENT_ACCEPT )

def isInboundRejectRuleActive(port_str):
    #edge -> platform

    return checkPortHasTarget(port_str, FILTER_TABLE_NAME, INPUT_CHAIN_NAME, JUDGEMENT_REJECT )

def isInboundDropRuleActive(port_str):
    #edge -> platform

    return checkPortHasTarget(port_str, FILTER_TABLE_NAME, INPUT_CHAIN_NAME, JUDGEMENT_DROP )

def isOutboundAcceptRuleActive(port_str):
    # platform => edge

    return checkPortHasTarget(port_str, FILTER_TABLE_NAME, OUTPUT_CHAIN_NAME, JUDGEMENT_ACCEPT )

def isOutboundRejectRuleActive(port_str):
    # platform => edge

    return checkPortHasTarget(port_str, FILTER_TABLE_NAME, OUTPUT_CHAIN_NAME, JUDGEMENT_REJECT )

def isOutboundDropRuleActive(port_str):
    # platform => edge

    return checkPortHasTarget(port_str, FILTER_TABLE_NAME, OUTPUT_CHAIN_NAME, JUDGEMENT_DROP )

def flushRules():
    logger.info("Flushing default caltrops rules")
    iptc.Table(iptc.Table.FILTER).flush()

def setDefaultRules():
    retval = True

    logger.info("Inserting default caltrops rules")

    iptablesInsertRuleInbound(FLASK_PORT_STR)
    iptablesInsertRuleOutbound(FLASK_PORT_STR)

    #sanity check squid port has accept judgement
    if(checkPortHasTarget(FLASK_PORT_STR) == True):
        logger.info("checkPortHasTarget reports flask port has accept judgement")
    else:
        logger.error("checkPortHasTarget reports flask port does not have accept judgement")
        retval = False


    logger.info("Inserting default rules")

    #range is not inclusive of the max so add one
    for i in range(ALLOWED_PROXY_PORT_MIN, ALLOWED_PROXY_PORT_MAX + 1):

        #need the string form
        port = str( i )

        #inbound ports
        iptablesInsertRuleInbound(port)

        #sanity check squid port has accept judgement
        if(isInboundAcceptRuleActive(port) == True):
            logger.debug("isInboundAcceptRuleActive reports port %s has accept judgement" % port)
        else:
            logger.error("isInboundAcceptRuleActive reports port %s does not have accept judgement" % port)
            retval = False

        #outbound ports
        iptablesInsertRuleOutbound(port)

        if(isOutboundAcceptRuleActive(port) == True):
            logger.debug("isOutboundAcceptRuleActive reports platform port %s has accept judgement" % port)
        else:
            logger.error("isOutboundAcceptRuleActive reports platform port %s does not have accept judgement" % port)

            retval = False

    return retval

def startup():
    #add the basic routing and perform any setup
    #after execution, source should be able to destination through container as an open proxy

    logger.info("Running caltrops application setup")

    #expect the platform to run on this same host, but outside this container
    #won't be able to block platform ports

    #default iptables rules
    #docker networking needs to be set up accordingly

    #input_chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), INPUT_CHAIN_NAME)
    #output_chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), OUTPUT_CHAIN_NAME)

    #problematic, affects the accept rules
    #input_chain.set_policy(JUDGEMENT_DROP)
    #output_chain.set_policy(JUDGEMENT_DROP)

    flushRules()
    if( setDefaultRules() == False ):
        raise Exception("Problem setting default rules")

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

    #print all rules
    logger.info("Startup completed. Current rules:\n %s" %  rules_str)

if __name__ == '__main__':

    #TODO: config directives
    server = Process(target=app.run, args=('0.0.0.0', FLASK_PORT))

    startup()

    #run flask app
    server.start()
