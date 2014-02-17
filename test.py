from __future__ import print_function

from gevent.select import select

import os
import libdbus

bus_address = os.environ['DBUS_SESSION_BUS_ADDRESS']
connection = libdbus.DBusConnection.open_private(bus_address)
# connection = libdbus.dbus_connection_open_private(bus_address)

libdbus.dbus_connection_get_server_id(connection)
connection.bus_register()
print("({!r}).bus_request_name(...) => {}".format(
    connection,
    connection.bus_request_name("org.yasashiisyndicate.dbusexample", 0)
))


class xvtable(libdbus.DBusObjectPathVTable):
    def unregister_function(self, connection, user_ptr):
        print("unregister_function")

    def message_function(self, connection, message, user_ptr):
        print("access on {!r}".format(message.contents))
        msg = message.contents
        conn = connection.contents.get_canonical()

        if (
            msg.get_interface() == 'org.yasashiisyndicate' and
            msg.get_member() == 'foo' and
            msg.get_path() == '/'
        ):
            new_msg = msg.new_method_return().contents
            print("sent with serial: %d" % (conn.send(new_msg), ))
            return libdbus.DBUS_HANDLER_RESULT_HANDLED
        if (
            msg.get_interface() == 'org.freedesktop.DBus.Introspectable' and
            msg.get_member() == 'Introspect' and
            msg.get_path() in ['/', '/foo']
        ):
            xml = u"""
            <!DOCTYPE node PUBLIC
                "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
                "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
            <node>
                <interface name="org.freedesktop.DBus.Introspectable">
                    <method name="Introspect">
                        <arg type="s" name="xml_data" direction="out"/>
                    </method>
                </interface>
                <interface name="org.freedesktop.DBus.Peer">
                    <method name="Ping"/>
                    <method name="GetMachineId">
                        <arg name="machine_uuid" type="s" direction="out"/>
                    </method>
                </interface>
                <interface name="org.yasashiisyndicate.Frobulator">
                    <method name="Frobulate">
                        <arg name="foo" type="s" direction="in"/>
                        <arg name="bar" type="s" direction="out"/>
                    </method>
                </interface>
                <interface name="org.yasashiisyndicate.Killable">
                    <method name="Kill" />
                </interface>
                <node name="foo"/>
            </node>
            """
            new_msg = msg.new_method_return().contents
            new_msg.append_args([('s', xml)])
            print("sent with serial: %d" % (conn.send(new_msg), ))
            return libdbus.DBUS_HANDLER_RESULT_HANDLED
        if (
            msg.get_interface() == 'org.yasashiisyndicate.Frobulator' and
            msg.get_member() == 'Frobulate'
        ):
            frobulate = lambda x: ''.join(sorted(x))
            new_msg = msg.new_method_return().contents
            args = list(msg.iter_args())
            new_msg.append_args([('s', frobulate(args[0]))])
            print("sent with serial: %d" % (conn.send(new_msg), ))
            return libdbus.DBUS_HANDLER_RESULT_HANDLED
        if (
            msg.get_interface() == 'org.yasashiisyndicate.Killable' and
            msg.get_member() == 'Kill' and
            msg.get_path() == '/'
        ):
            conn.quacking = False
            print("{!r}.quacking = False".format(conn))
            conn.send(msg.new_method_return().contents)
            return libdbus.DBUS_HANDLER_RESULT_HANDLED
        return libdbus.DBUS_HANDLER_RESULT_NOT_YET_HANDLED


connection.register_object_path("/", xvtable(), 0)
connection.register_object_path("/foo", xvtable(), 1)
connection.register_object_path("/foo/foo", xvtable(), 2)
connection.register_object_path("/foo/foo/foo", xvtable(), 3)
connection.quacking = True


while connection.quacking:
    (rs, ws, xs) = select([connection], [], [])
    if connection in rs:
        libdbus.dbus_connection_read_write_dispatch(connection, 0)
        connection.dispatch()

connection.close()
