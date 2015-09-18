#!/usr/bin/env python
# coding=utf-8
# vim: set fileencoding=utf-8 :
from sniffer.sniff import NetworkSniffer, FacebookSniffer
#from nanomsg import Socket, PAIR, PUB
from pymongo import MongoClient
#import bson
import gevent
import time
import urllib3

def run_network_sniff(coll):
    s = NetworkSniffer(coll)
    s.startup()

def run_facebook_sniff(coll):
    access_token ='CAACEdEose0cBABNZBVvNSrnb14YfqunCj9AU1h3ZBHU5Ipl536IBU2pUFk4ZAMajFPB2iVRWMCMxwvupcczJMYXwZCLyMhs7WlFJnzslHUY80UhDPaCy6GszSalfpnOCHEVfa2yIFc1zvuZCJF9eef58Ie4z0CZAFa22q5CHONA5vsYf3HZAepZAk2f8FUuTeEMZD'
    userid='10153123353586624'

    fbsniffer = FacebookSniffer(access_token, userid, coll)
    fbsniffer.sniff_posts()
    pause()

def pause():
    time.sleep(0.001)


def main():
    urllib3.disable_warnings()
    host = "localhost:27017"
    db = MongoClient(host)['pyconuk']
    netcoll = db['network']
    fbcoll = db['fb']

#    run_network_sniff(netcoll)
    gevent.joinall([
        gevent.spawn(run_facebook_sniff, fbcoll),
        gevent.spawn(run_network_sniff, netcoll),
        ])

if __name__ == '__main__':
    main()
