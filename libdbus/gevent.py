from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals
)
from .dbus_bindings import (
    dbus_connection_read_write_dispatch,
    DBusPendingCallStructure
)
import gevent
from gevent.select import select
from gevent.event import AsyncResult


def start_dispatch_loop_greenlet(connection):
    try:
        while True:
            try:
                (rs, ws, xs) = select([connection], [], [])
            except ValueError:
                break
            if connection in rs:
                dbus_connection_read_write_dispatch(connection, 0)
                connection.dispatch()
    finally:
        connection.close()


def start_dispatch_loop(connection):
    return gevent.Greenlet.spawn(
        start_dispatch_loop_greenlet, connection)


class DBusPendingCall(DBusPendingCallStructure, AsyncResult):
    pass

