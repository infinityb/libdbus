from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals
)
from . import dbus_bindings as libdbus


def subpaths(path):
    slashs_at = ['/']
    if path[0] != '/':
        raise ValueError('absolute path only')
    cur_slash_idx = 0
    while True:
        cur_slash_idx = path.find('/', cur_slash_idx + 1)
        if cur_slash_idx == -1:
            break
        slashs_at.append(path[:cur_slash_idx])
    slashs_at.append(path)
    return slashs_at


class ObjectHierarchy(libdbus.DBusObjectPathVTable):
    def __init__(self, connection):
        super(ObjectHierarchy, self).__init__()
        self._connection = connection.get_canonical()
        self._interfaces = {}
        self._object_table = {}

    def register_object_hierarchy(self, path, instance, interfaces=None):
        print("({!r}).register_object({!r}, {!r}, {!r})".format(
            self, path, instance, interfaces))
        if path not in self._object_table:
            self._object_table[path] = {}
        if interfaces is None:
            interfaces = libdbus.object_interfaces(instance)
            print("adding {!r} to {!r}:{!r}".format(
                instance, path, interfaces))
        if isinstance(interfaces, str):
            interfaces = [interfaces]
        for _interface in interfaces:
            if _interface in self._object_table[path]:
                raise Exception(
                    'interface({}) already registered for path({})'
                    .format(_interface.name, path)
                )
            if _interface.name not in self._interfaces:
                self._interfaces[_interface.name] = _interface
            else:
                assert _interface == self._interfaces[_interface.name]
        for _interface in interfaces:
            self._object_table[path][_interface.name] = instance
        self._connection.try_register_fallback(path, self, 0)

    def unregister_function(self, connection, user_ptr):
        print("unregister_function")

    def message_function(self, connection, message, user_ptr):
        msg = message.contents
        print("message: {!r}".format(msg))
        conn = connection.contents.get_canonical()
        assert conn is self._connection

        for path in reversed(subpaths(msg.get_path())):
            if path in self._object_table:
                break
        else:
            raise Exception()

        interface_obj = self._interfaces[msg.get_interface()]
        by_interface = self._object_table.get(path, None)
        if by_interface is None:
            print("by_interface is None, unhandled")
            return libdbus.DBUS_HANDLER_RESULT_NOT_YET_HANDLED
        dbus_object = by_interface.get(interface_obj.name, None)
        if dbus_object is None:
            print("dbus_object is None, unhandled")
            return libdbus.DBUS_HANDLER_RESULT_NOT_YET_HANDLED
        method = getattr(dbus_object, msg.get_member(), None)
        if method is None:
            print("method is None, unhandled")
            return libdbus.DBUS_HANDLER_RESULT_NOT_YET_HANDLED
        try:
            retval = method(*list(msg.iter_args()))
        except Exception:
            import traceback
            traceback.print_exc()
            return libdbus.DBUS_HANDLER_RESULT_NOT_YET_HANDLED

        new_msg = msg.new_method_return().contents
        argspec = interface_obj.get_retspec(msg.get_member())
        if len(argspec) == 1:
            new_msg.append_args([(argspec[0], retval)])
        else:
            new_msg.append_object(argspec, retval)
        conn.send(new_msg)
        return libdbus.DBUS_HANDLER_RESULT_HANDLED
