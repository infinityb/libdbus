from __future__ import (
    absolute_import,
    division,
    print_function,
    # unicode_literals
)
import unittest
import ast

import gevent

import libdbus
DBusConnection = libdbus.DBusConnection
from libdbus.gevent import start_dispatch_loop


frobulator_interface = \
    libdbus.DBusInterface('org.yasashiisyndicate.Frobulator')
frobulator_interface.add_method('Frobulate', 's', ['value'], 's')
frobulator_interface.add_method('Bifrobulate', 'a{sd}', ['value'], 's')
frobulator_interface.add_method('Unbifrobulate', 's', ['value'], 'a{sd}')


class OrderRemovalFrobulator(
    frobulator_interface.astype(),
    libdbus.DBusObject
):
    @libdbus.export
    def Frobulate(self, value):
        return ''.join(sorted(value))

    @libdbus.export
    def Bifrobulate(self, value):
        return repr(value)

    @libdbus.export
    def Unbifrobulate(self, value):
        return ast.literal_eval(value)


class GeneralTest(unittest.TestCase):
    SERVER_BUS_NAME = "org.yasashiisyndicate.dbusexample"

    def setUp(self):
        self.serving_connection = libdbus.DBusConnection(
            libdbus.DBusConnection.SESSION,
            private=True
        )
        connection = self.serving_connection
        libdbus.dbus_connection_get_server_id(connection)
        connection.bus_register()
        connection.bus_request_name("org.yasashiisyndicate.dbusexample", 0)

        object_table = libdbus.ObjectHierarchy(self.serving_connection)
        frobulator = OrderRemovalFrobulator()
        frobulator['foo'] = frobulator
        object_table.register_object_hierarchy(
            '/org/yasashiisyndicate/dbusexample',
            frobulator)
        self._serving_greenlet = start_dispatch_loop(self.serving_connection)

    def test_frobulator(self):
        with DBusConnection('session', private=True) as cli:
            proxy_object = cli.get_object(
                "org.yasashiisyndicate.dbusexample",
                "/org/yasashiisyndicate/dbusexample",
                interface=frobulator_interface)
            response_fut = proxy_object.dbus_call(
                'Frobulate', 'Frobulation Test')
            try:
                response = response_fut.get(timeout=1)
            except:
                import pdb; pdb.set_trace()
                raise
            self.assertEqual(response, ' FTabeilnoorsttu')

    def test_unbifrobulator(self):
        with DBusConnection('session', private=True) as cli:
            proxy_object = cli.get_object(
                "org.yasashiisyndicate.dbusexample",
                "/org/yasashiisyndicate/dbusexample",
                interface=frobulator_interface)
            test_object = {'a': 1, 'b': 2}
            response = proxy_object.dbus_call(
                'Unbifrobulate', repr(test_object)).get(timeout=1)
            self.assertEqual(response, test_object)
            gevent.sleep(100)

    def tearDown(self):
        self.serving_connection.close()
        self._serving_greenlet.join()
        if self._serving_greenlet.exception:
            raise self._serving_greenlet.exception






# libdbus.dbus_connection_get_server_id(connection)
# connection.bus_register()
# print("({!r}).bus_request_name(...) => {}".format(
#     connection,
#     connection.bus_request_name("org.yasashiisyndicate.dbusexample", 0)
# ))
