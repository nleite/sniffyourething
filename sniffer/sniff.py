#!/usr/bin/env python
# coding=utf-8
# vim: set fileencoding=utf-8 :
import socket
import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *
from scapy_http import http
import facebook
import requests

class Sniffer(object):
    """Sniffer: Base sniffer class that will hold all comon sniffers methods like persisting documents"""

    def __init__(self, collection):
        self._collection = collection

    def persist(self, document):
        print('here')
        self._collection.insert_many(document)

class FacebookSniffer(Sniffer):

    def __init__(self, access_token, userid, collection):
        super(FacebookSniffer, self).__init__(collection)
        self.access_token =access_token
        self.userid=userid

    def process_posts(self, posts):
        """lets process the incoming json messages"""
        self.persist(posts['data'])

    def sniff_posts(self):
        graph = facebook.GraphAPI(self.access_token)
        profile = graph.get_object(self.userid)
        posts = graph.get_connections(profile['id'], 'posts')

        while True:
            if 'data' not in posts or len(posts['data']) < 1:
                print('NO MORE DATA')
                break
            self.process_posts(posts)
            if 'paging' not in posts:
                print(posts)
                break
            r = requests.get(posts['paging']['next'])
            if r.status_code >= 200 and r.status_code < 300:
                posts = r.json()
            else:
                break


class NetworkSniffer(Sniffer):
    """NetworkSniffer is a simple scappy implementation that will sniff a given protocol and store it into a collection
    """
    def __init__(self, collection):
        super(NetworkSniffer, self).__init__(collection)
        self.packagecount = 0

    def startup(self):
        sniff(filter='tcp', prn=self.action)

    def action(self,packet):
        self.packagecount += 1
        doc = packet.fields
        doc['tcp'] = packet[TCP].fields
        doc['ip'] = packet[IP].fields

        #TODO I don't like this code and but for fast iteration let's put it like this
        if http.HTTPResponse in packet:
            doc['httpresponse'] = packet[TCP][http.HTTPResponse].fields
#            doc['httpresponse']['payload'] = packet[TCP][http.HTTPResponse].payload
        if http.HTTPRequest in packet:
            doc['httprequest'] = packet[TCP][http.HTTPRequest].fields


        self.persist([doc])

