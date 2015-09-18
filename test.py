#!/usr/bin/env python
# coding=utf-8
# vim: set fileencoding=utf-8 :
from sniffer.sniff import NetworkSniffer, FacebookSniffer
#from nanomsg import Socket, PAIR, PUB
from pymongo import MongoClient
#import bson
import gevent
import time

def run_network_sniff(coll):
    pause()
    s = NetworkSniffer(coll)
    s.startup()

def run_facebook_sniff(coll):
    pause()
    access_token = 'CAACEdEose0cBABZAfxZA6BL6yYBLb6s1e8TLlLaeOAquiNDm6ucXaozZBpqBZB6Ff70vgEcV9efZCLd2CLyJhLL0TQP50oIgrt8wbqOM0ksuKXZCZBquDUr3yVfcCNYardMESjEGqcxYGPrpFVNiFZBN0ksaSNNQIZCGIeRtm2UJCzQPk8kJuNtef7RynNiyn5SkZD'
    userid='10153123353586624'

    fbsniffer = FacebookSniffer(access_token, userid)
    fbsniffer.sniff_posts()

def pause():
    time.sleep(0.001)




def main():

    host = "localhost:27017"
    db = MongoClient(host)['pyconuk']
    netcoll = db['network']
    fbcoll = db['fb']


    gevent.joinall([
        gevent.spawn(run_network_sniff, netcoll),
        gevent.spawn(run_facebook_sniff, fbcoll),
        ])


if __name__ == '__main__':
    main()
