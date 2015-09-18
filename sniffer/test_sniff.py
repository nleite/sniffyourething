#!/usr/bin/env python
# coding=utf-8
# vim: set fileencoding=utf-8 :
import unittest
from sniff import Sniffer

class TestSniffer(unittest.TestCase):

    def setUp(self):
        self.sniffer = Sniffer("TCP", 8080)

    def test_socket_notNone(self):
        self.assertIsNotNone(self.sniffer.socket )

    def test_startup_ok(self):
        self.assertTrue(self.sniffer.startup())
