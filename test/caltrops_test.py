import unittest
import requests
import json
import re
import time

#from the project root:
#python3 -m unittest test/caltrops_test.py

#TODO: figure this out automatically
PROTOCOL = "http"
CALTROPS_IP = "172.20.0.2" #definitely double check this
CALTROPS_PORT = 5000
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
        response = requests.get("%s://%s:%d/reject_twx_inbound" % (PROTOCOL, CALTROPS_IP, CALTROPS_PORT), params=payload)

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
        response = requests.get("%s://%s:%d/drop_twx_inbound" % (PROTOCOL, CALTROPS_IP, CALTROPS_PORT), params=payload)

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
        response = requests.get("%s://%s:%d/drop_twx_inbound" % (PROTOCOL, CALTROPS_IP, CALTROPS_PORT), params=payload)

        time.sleep(1)

        port_rules.clear()
        port_rules = self.get_rule_str(target_port, FILTER_TABLE_NAME, INPUT_CHAIN_NAME)

        self.assertEqual( len(port_rules), 1)

        regex = ".*%s.*" % JUDGEMENT_DROP

        self.assertNotEqual( re.match(regex, port_rules[0]), None, "Expecting DROP judgement in rule %s" % port_rules[0])

        #change judgement to accept
        payload = {'port': target_port}
        response = requests.get("%s://%s:%d/accept_twx_inbound" % (PROTOCOL, CALTROPS_IP, CALTROPS_PORT), params=payload)

        time.sleep(1)

        port_rules.clear()
        port_rules = self.get_rule_str(target_port, FILTER_TABLE_NAME, INPUT_CHAIN_NAME)

        self.assertEqual( len(port_rules), 1)

        regex = ".*%s.*" % JUDGEMENT_ACCEPT

        self.assertNotEqual( re.match(regex, port_rules[0]), None, "Expecting ACCEPT judgement in rule %s" % port_rules[0])


    def test_output_toggle_judgement(self):
        pass

    ##################
    #util functions
    def get_rules_sorted(self, filter=FILTER_TABLE_NAME, chain=INPUT_CHAIN_NAME):
        response = requests.get("%s://%s:%d/get_rules" % (PROTOCOL, CALTROPS_IP, CALTROPS_PORT))

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
        response = requests.get("%s://%s:%d/get_rules" % (PROTOCOL, CALTROPS_IP, CALTROPS_PORT))

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
        response = requests.get("%s://%s:%d/get_rules" % (PROTOCOL, CALTROPS_IP, CALTROPS_PORT))

        self.assertEqual(HTTP_OK, response.status_code)

        rule_json = json.loads( json.dumps(response.json()) )


if __name__ == '__main__':

    #TODO set target host and port

    #TODO: optionally ensure docker container is started up and running

    unittest.main()

    #TODO: optionally ensure docker container is shutdown
