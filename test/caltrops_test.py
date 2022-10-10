import unittest
import requests
import json
import re
import time
import sys

#from the project test dir:
#python3 ./caltrops_test.py

PROTOCOL = "http"

MANAGE_CONTAINER = False

PORT_MIN = 3128
PORT_MAX = 3148

HTTP_OK = 200
HTTP_FAIL = 500

FILTER_TABLE_NAME = "filter"

INPUT_CHAIN_NAME = "INPUT"
OUTPUT_CHAIN_NAME = "OUTPUT"

JUDGEMENT_ACCEPT = "ACCEPT"
JUDGEMENT_DROP = "DROP"
JUDGEMENT_REJECT = "REJECT"

#run from the project root

class caltrops_tests(unittest.TestCase):

    def test_container_available(self):
        #TODO: implement with the rest of container spinup/down support
        if( MANAGE_CONTAINER == True ):
            pass

    def test_default_input_setup(self):

        #expect 20 squid ports and 1 caltrops port open, with accept judgement

        #test host and port are up and we get the expected iptables rules
        rules = self.get_rules_sorted(FILTER_TABLE_NAME, INPUT_CHAIN_NAME)

        #squid ports + caltrops port
        self.assertEqual(len(rules), PORT_MAX - PORT_MIN + 1)

        i = 0
        for port in range(PORT_MIN, PORT_MAX):
            regex = ".*%d.*%s.*" % (port, JUDGEMENT_ACCEPT)
            self.assertNotEqual( re.match(regex, rules[i]), None, "Accept judgement on input port %d" % port  )
            i+=1

        #caltrops port last
        regex = ".*%d.*%s.*" % (CALTROPS_PORT, JUDGEMENT_ACCEPT)
        self.assertNotEqual( re.match(regex, rules[i] ), None )

    def test_default_output_setup(self):
        #test host and port are up and we get the expected iptables rules
        rules = self.get_rules_sorted(FILTER_TABLE_NAME, OUTPUT_CHAIN_NAME)

        #squid ports + caltrops port
        self.assertEqual(len(rules), PORT_MAX - PORT_MIN + 1)

        i = 0
        for port in range(PORT_MIN, PORT_MAX):
            regex = ".*%d.*%s.*" % (port, JUDGEMENT_ACCEPT)
            self.assertNotEqual( re.match(regex, rules[i]), None, "Accept judgement on output port %d" % port  )
            i+=1

        #caltrops port last
        regex = ".*%d.*%s.*" % (CALTROPS_PORT, JUDGEMENT_ACCEPT)
        self.assertNotEqual( re.match(regex, rules[i] ), None )

    def test_rule_reset(self):

        #toggle judgements on a bunch of ports

        #inbound
        payload = {'port': 3128}
        response = requests.get("%s/reject_inbound" % (CALTROPS_URL_BASE), params=payload)
        self.assertEqual(HTTP_OK, response.status_code)

        payload = {'port': 3130}
        response = requests.get("%s/reject_inbound" % (CALTROPS_URL_BASE), params=payload)
        self.assertEqual(HTTP_OK, response.status_code)

        payload = {'port': 3132}
        response = requests.get("%s/reject_inbound" % (CALTROPS_URL_BASE), params=payload)
        self.assertEqual(HTTP_OK, response.status_code)

        payload = {'port': 3134}
        response = requests.get("%s/reject_inbound" % (CALTROPS_URL_BASE), params=payload)
        self.assertEqual(HTTP_OK, response.status_code)

        payload = {'port': 3129}
        response = requests.get("%s/drop_inbound" % (CALTROPS_URL_BASE), params=payload)
        self.assertEqual(HTTP_OK, response.status_code)

        payload = {'port': 3131}
        response = requests.get("%s/drop_inbound" % (CALTROPS_URL_BASE), params=payload)
        self.assertEqual(HTTP_OK, response.status_code)

        payload = {'port': 3133}
        response = requests.get("%s/drop_inbound" % (CALTROPS_URL_BASE), params=payload)
        self.assertEqual(HTTP_OK, response.status_code)

        payload = {'port': 3135}
        response = requests.get("%s/drop_inbound" % (CALTROPS_URL_BASE), params=payload)
        self.assertEqual(HTTP_OK, response.status_code)

        #outbound
        payload = {'port': 3138}
        response = requests.get("%s/reject_outbound" % (CALTROPS_URL_BASE), params=payload)
        self.assertEqual(HTTP_OK, response.status_code)

        payload = {'port': 3140}
        response = requests.get("%s/reject_outbound" % (CALTROPS_URL_BASE), params=payload)
        self.assertEqual(HTTP_OK, response.status_code)

        payload = {'port': 3142}
        response = requests.get("%s/reject_outbound" % (CALTROPS_URL_BASE), params=payload)
        self.assertEqual(HTTP_OK, response.status_code)

        payload = {'port': 3144}
        response = requests.get("%s/reject_outbound" % (CALTROPS_URL_BASE), params=payload)
        self.assertEqual(HTTP_OK, response.status_code)

        payload = {'port': 3139}
        response = requests.get("%s/drop_outbound" % (CALTROPS_URL_BASE), params=payload)
        self.assertEqual(HTTP_OK, response.status_code)

        payload = {'port': 3141}
        response = requests.get("%s/drop_outbound" % (CALTROPS_URL_BASE), params=payload)
        self.assertEqual(HTTP_OK, response.status_code)

        payload = {'port': 3143}
        response = requests.get("%s/drop_outbound" % (CALTROPS_URL_BASE), params=payload)
        self.assertEqual(HTTP_OK, response.status_code)

        payload = {'port': 3145}
        response = requests.get("%s/drop_outbound" % (CALTROPS_URL_BASE), params=payload)
        self.assertEqual(HTTP_OK, response.status_code)

        #reset rules
        response = requests.get("%s/reset_rules" % (CALTROPS_URL_BASE), params=payload)
        self.assertEqual(HTTP_OK, response.status_code)

        #confirm all accept inbound
        #expect 20 squid ports and 1 caltrops port open, with accept judgement

        #test host and port are up and we get the expected iptables rules
        rules = self.get_rules_sorted(FILTER_TABLE_NAME, INPUT_CHAIN_NAME)

        #squid ports + caltrops port
        self.assertEqual(len(rules), PORT_MAX - PORT_MIN + 1)

        i = 0
        for port in range(PORT_MIN, PORT_MAX):
            regex = ".*%d.*%s.*" % (port, JUDGEMENT_ACCEPT)
            self.assertNotEqual( re.match(regex, rules[i]), None, "Accept judgement on input port %d" % port  )
            i+=1

        #caltrops port last
        regex = ".*%d.*%s.*" % (CALTROPS_PORT, JUDGEMENT_ACCEPT)
        self.assertNotEqual( re.match(regex, rules[i] ), None )

        #confirm all accept outbound
        #test host and port are up and we get the expected iptables rules
        rules = self.get_rules_sorted(FILTER_TABLE_NAME, OUTPUT_CHAIN_NAME)

        #squid ports + caltrops port
        self.assertEqual(len(rules), PORT_MAX - PORT_MIN + 1)

        i = 0
        for port in range(PORT_MIN, PORT_MAX):
            regex = ".*%d.*%s.*" % (port, JUDGEMENT_ACCEPT)
            self.assertNotEqual( re.match(regex, rules[i]), None, "Accept judgement on output port %d" % port  )
            i+=1

        #caltrops port last
        regex = ".*%d.*%s.*" % (CALTROPS_PORT, JUDGEMENT_ACCEPT)
        self.assertNotEqual( re.match(regex, rules[i] ), None )

    def test_input_toggle_judgement(self):

        #reset rules

        target_port = 3132

        #expect this port to be valid
        #expect there's an accept rule for this in INPUT
        self.assertTrue(target_port >= PORT_MIN)
        self.assertTrue(target_port <= PORT_MAX)

        port_rules = self.get_rule_str(target_port, FILTER_TABLE_NAME, INPUT_CHAIN_NAME)

        starting_rules = self.get_rules_sorted(FILTER_TABLE_NAME, INPUT_CHAIN_NAME)

        self.assertEqual( len(starting_rules), 21)
        self.assertEqual( len(port_rules), 1)

        regex = ".*%s.*" % JUDGEMENT_ACCEPT

        self.assertNotEqual( re.match(regex, port_rules[0]), None, "Expecting ACCEPT judgement in rule %s" % port_rules[0])

        #change judgement to reject
        payload = {'port': target_port}
        response = requests.get("%s/reject_inbound" % (CALTROPS_URL_BASE), params=payload)
        self.assertEqual(HTTP_OK, response.status_code)

        time.sleep(1)

        port_rules.clear()
        port_rules = self.get_rule_str(target_port, FILTER_TABLE_NAME, INPUT_CHAIN_NAME)

        self.assertEqual( len(port_rules), 1)

        regex = ".*%s.*" % JUDGEMENT_REJECT

        #check the target port's new judgement
        self.assertNotEqual( re.match(regex, port_rules[0]), None, "Expecting REJECT judgement in rule %s" % port_rules[0])

        #TODO: check no other rules are changed
        #current_rules = self.get_rules_sorted(FILTER_TABLE_NAME, INPUT_CHAIN_NAME)

        ########
        #change judgement to drop
        payload = {'port': target_port}
        response = requests.get("%s/drop_inbound" % (CALTROPS_URL_BASE), params=payload)
        self.assertEqual(HTTP_OK, response.status_code)

        time.sleep(1)

        port_rules.clear()
        port_rules = self.get_rule_str(target_port, FILTER_TABLE_NAME, INPUT_CHAIN_NAME)

        self.assertEqual( len(port_rules), 1)

        regex = ".*%s.*" % JUDGEMENT_DROP

        self.assertNotEqual( re.match(regex, port_rules[0]), None, "Expecting REJECT judgement in rule %s" % port_rules[0])

        #TODO: check that no other rules are changed


        ########
        #change judgement to drop
        payload = {'port': target_port}
        response = requests.get("%s/drop_inbound" % (CALTROPS_URL_BASE), params=payload)
        self.assertEqual(HTTP_OK, response.status_code)

        time.sleep(1)

        port_rules.clear()
        port_rules = self.get_rule_str(target_port, FILTER_TABLE_NAME, INPUT_CHAIN_NAME)

        self.assertEqual( len(port_rules), 1)

        regex = ".*%s.*" % JUDGEMENT_DROP

        self.assertNotEqual( re.match(regex, port_rules[0]), None, "Expecting DROP judgement in rule %s" % port_rules[0])

        #change judgement to accept
        payload = {'port': target_port}
        response = requests.get("%s/accept_inbound" % (CALTROPS_URL_BASE), params=payload)
        self.assertEqual(HTTP_OK, response.status_code)

        time.sleep(1)

        port_rules.clear()
        port_rules = self.get_rule_str(target_port, FILTER_TABLE_NAME, INPUT_CHAIN_NAME)

        self.assertEqual( len(port_rules), 1)

        regex = ".*%s.*" % JUDGEMENT_ACCEPT

        self.assertNotEqual( re.match(regex, port_rules[0]), None, "Expecting ACCEPT judgement in rule %s" % port_rules[0])

    def test_set_rule_invalid_port(self):
        pass

    def test_output_toggle_judgement(self):
        pass



    ##################
    #util functions
    def get_rules_sorted(self, filter=FILTER_TABLE_NAME, chain=INPUT_CHAIN_NAME):
        response = requests.get("%s/get_rules" % (CALTROPS_URL_BASE))

        self.assertEqual(HTTP_OK, response.status_code)

        rule_json = json.loads( json.dumps(response.json()) )

        rules = []
        for rule in rule_json[filter][chain]:
            #print("rule: %s" % rule)
            rules.append(rule)

        #for rule in sorted(rules):
        #    print("rule: %s" % rule)
        return sorted(rules)

    def get_rule_str(self, port, filter=FILTER_TABLE_NAME, chain=INPUT_CHAIN_NAME):
        response = requests.get("%s/get_rules" % (CALTROPS_URL_BASE))

        self.assertEqual(HTTP_OK, response.status_code)

        rule_json = json.loads( json.dumps(response.json()) )

        rules = []
        for rule in rule_json[filter][chain]:
            regex = ".*%d.*" % port

            if (re.match(regex, rule) != None):
                rules.append(rule)

        return rules


    def get_rule_port_judgements(self):
        #TODO: implement fully
        #return a hash of sorted port numbers and their respective judgements
        response = requests.get("%s/get_rules" % (CALTROPS_URL_BASE))

        self.assertEqual(HTTP_OK, response.status_code)

        rule_json = json.loads( json.dumps(response.json()) )


if __name__ == '__main__':

    global CALTROPS_IP
    global CALTROPS_PORT
    global CALTROPS_URL_BASE
    CALTROPS_IP = "192.168.137.1" #default bad guess
    CALTROPS_PORT = 5000

    #set target host and port
    if(len(sys.argv) == 3):
        #host and port
        CALTROPS_IP = sys.argv[1]
        CALTROPS_PORT = int( sys.argv[2] )
    elif(len(sys.argv) == 2):
        if(sys.argv[1] == "-h" or sys.argv[1] == "--help"):
            print("Usage: caltrops_test.py [ip] [port]")
            exit(1)
        else:
            #host
            CALTROPS_IP = sys.argv[1]
    else:
        #default host and port
        pass

    #delete because this is passed on by default to the unit test framework
    del sys.argv[1:]

    print("Running tests using ip %s and port %d" % (CALTROPS_IP, CALTROPS_PORT) )
    CALTROPS_URL_BASE = "%s://%s:%d" % (PROTOCOL, CALTROPS_IP, CALTROPS_PORT)


    #TODO: optionally ensure docker container is started up and running

    unittest.main()

    #TODO: optionally ensure docker container is shutdown
