from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals
)

import os
import ctypes
from cStringIO import StringIO
import xml.dom.minidom
from weakref import WeakValueDictionary
from gevent.event import AsyncResult


dbus = ctypes.CDLL('libdbus-1.so.3')

DBUS_TYPE_INVALID = 0

DBUS_DISPATCH_DATA_REMAINS = 0
DBUS_DISPATCH_COMPLETE = 1
DBUS_DISPATCH_NEED_MEMORY = 2

DBUS_HANDLER_RESULT_HANDLED = 0
DBUS_HANDLER_RESULT_NOT_YET_HANDLED = 1
DBUS_HANDLER_RESULT_NEED_MEMORY = 2
DBUS_TIMEOUT_INFINITE = 0x7FFFFFFF
DBUS_TIMEOUT_USE_DEFAULT = -1


DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE = \
    '<!DOCTYPE node PUBLIC ' \
    '"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"' \
    '\n"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">\n'


def export(func):
    setattr(func, '_dbus_allow_export', True)
    return func


def is_exported(func):
    return hasattr(func, '_dbus_allow_export') and \
        getattr(func, '_dbus_allow_export')


def object_interfaces(dbus_object):
    if isinstance(dbus_object, DBusObject):
        cls = type(dbus_object)
    elif issubclass(dbus_object, DBusObject):
        cls = dbus_object
    else:
        raise TypeError('must be a DBusObject instance of subclass')
    interfaces = list()
    for type_ in cls.mro():
        if hasattr(type_, '_dbus_interfaces'):
            interfaces.extend(type_._dbus_interfaces)
    return list(set(interfaces))


def _typespec_atomise_helper(argspec, idx, depth):
    atoms = []
    while idx < len(argspec):
        if depth > 0 and argspec[idx] == '}':
            break
        if argspec[idx] in 'sdt':
            atoms.append(argspec[idx])
            idx += 1
        elif argspec[idx] in 'a':
            assert argspec[idx + 1] == '{'
            atom, idx = _typespec_atomise_helper(argspec, idx + 2, depth + 1)
            assert argspec[idx] == '}'
            idx += 1
            atoms.append(('a', atom))
        else:
            raise Exception(argspec[idx:])
    return atoms, idx


def typespec_atomise(argspec):
    atoms, length = _typespec_atomise_helper(argspec, 0, 0)
    assert len(argspec) == length
    return atoms


def typespec_len(argspec):
    return len(typespec_atomise(argspec))


class DBusInterface(object):
    def __init__(self, name):
        self._members = list()
        self.name = name

    def get_argspec(self, methname):
        for member in self._members:
            if member[1] == methname:
                return member[2]
        else:
            raise KeyError('no methname {!r}'.format(methname))

    def get_retspec(self, methname):
        for member in self._members:
            if member[1] == methname:
                return member[4]
        else:
            raise KeyError('no methname {!r}'.format(methname))

    def add_method(self, name, argspec, argnames, retspec):
        assert typespec_len(argspec) == len(argnames)
        self._members.append(('method', name, argspec, argnames, retspec))

    def add_signal(self, name, retspec):
        self._members.append(('signal', name, retspec))

    def astype(self):
        return type(self.name, (DBusObject, ), {
            '_dbus_interfaces': [self]
        })


dbus_introspectable = DBusInterface('org.freedesktop.DBus.Introspectable')
dbus_introspectable.add_method('Introspect', '', [], 's')

dbus_peer = DBusInterface('org.freedesktop.DBus.Peer')
dbus_peer.add_method('Ping', '', [], '')
dbus_peer.add_method('GetMachineId', '', [], 's')


class DBusObject(dict):
    _dbus_interfaces = [
        dbus_introspectable,
        dbus_peer
    ]

    @export
    def Introspect(self):
        return introspect_object(self, True)

    def dbus_children(self):
        return dict.keys(self)

    def __repr__(self):
        return "DBusObject({})".format(
            super(DBusObject, self).__repr__()
        )


# class DBusObjectDescriptor(object):
#     @classmethod
#     def from_dbus_object(cls, dbus_object):
#         inst = cls()
#         inst._children.extend(list(dbus_object.keys()))
#         inst._interfaces.extend(object_interfaces(dbus_object))
#         return inst

#     def __init__(self, *args, **kwargs):
#         super(DBusObjectDescriptor, self).__init__(*args, **kwargs)
#         self._children = list()
#         self._interfaces = list()

#     def add_interface(self, interface):
#         self._interfaces.append(interface)


def introspect_child_node_name_writer(writer, child_name):
    writer.write('<node name="{}"/>'.format(child_name))


def introspect_interface_method_writer(writer, member):
    (type_, name, argspec, argnames, retspec) = member
    assert type_ == 'method'
    if argspec + retspec:
        writer.write('<method name="{}">'.format(name))
        in_arg_fmt = '<arg direction="in" type="{}" name="{}"/>'
        for arg_type, name in zip(argspec, argnames):
            writer.write(in_arg_fmt.format(arg_type, name))
        ret_fmt = '<arg direction="out" type="{}"/>'
        for ret in retspec:
            writer.write(ret_fmt.format(ret))
        writer.write('</method>')
    else:
        writer.write('<method name="{}"/>'.format(name))


def introspect_interface_signal_writer(writer, member):
    (type_, name, retspec) = member
    assert type_ == 'signal'
    raise NotImplemented


def introspect_interface_writer(writer, dbus_interface):
    writer.write('<interface name="{}">'.format(dbus_interface.name))
    for member in dbus_interface._members:
        if member[0] == 'method':
            introspect_interface_method_writer(writer, member)
        elif member[0] == 'signal':
            introspect_interface_signal_writer(writer, member)
        else:
            raise TypeError('unhandled member type')
    writer.write('</interface>')


def introspect_object_writer(writer, dbus_object):
    writer.write(DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE)
    writer.write('<node>')
    for interface in object_interfaces(dbus_object):
        introspect_interface_writer(writer, interface)
    for child_name in dbus_object.keys():
        introspect_child_node_name_writer(writer, child_name)
    writer.write('</node>')


def introspect_object(dbus_object, prettify=False):
    writer = StringIO()
    introspect_object_writer(writer, dbus_object)
    writer.seek(0)
    xmlstr = writer.read()
    if prettify:
        xmlstr = xml.dom.minidom.parseString(xmlstr).toprettyxml()
    return xmlstr


def dbus_error_is_set(dbus_error):
    assert isinstance(dbus_error, DBusErrorStructure)
    return dbus.dbus_error_is_set(ctypes.pointer(dbus_error)) > 0


def dbus_connection_open(dbus_addr):
    error = DBusErrorStructure()
    conn = dbus.dbus_connection_open(dbus_addr, ctypes.pointer(error))
    error.raise_if_set()
    return conn.contents


def dbus_connection_open_private(dbus_addr):
    error = DBusErrorStructure()
    conn = dbus.dbus_connection_open_private(dbus_addr, ctypes.pointer(error))
    error.raise_if_set()
    return conn.contents


def dbus_connection_ref(dbus_connection):
    assert isinstance(dbus_connection, DBusConnectionStructure)
    dbus.dbus_connection_ref(ctypes.pointer(dbus_connection))


def dbus_connection_unref(dbus_connection):
    assert isinstance(dbus_connection, DBusConnectionStructure)
    dbus.dbus_connection_unref(ctypes.pointer(dbus_connection))


def dbus_connection_close(dbus_connection):
    assert isinstance(dbus_connection, DBusConnectionStructure)
    dbus.dbus_connection_close(ctypes.pointer(dbus_connection))


def dbus_connection_get_is_connected(dbus_connection):
    assert isinstance(dbus_connection, DBusConnectionStructure)
    return dbus.dbus_connection_get_is_connected(
        ctypes.pointer(dbus_connection)) > 0


def dbus_connection_get_is_authenticated(dbus_connection):
    assert isinstance(dbus_connection, DBusConnectionStructure)
    return dbus.dbus_connection_get_is_authenticated(
        ctypes.pointer(dbus_connection)) > 0


def dbus_connection_get_is_anonymous(dbus_connection):
    assert isinstance(dbus_connection, DBusConnectionStructure)
    return dbus.dbus_connection_get_is_anonymous(
        ctypes.pointer(dbus_connection)) > 0


def dbus_connection_get_server_id(dbus_connection):
    assert isinstance(dbus_connection, DBusConnectionStructure)
    return dbus.dbus_connection_get_server_id(
        ctypes.pointer(dbus_connection))


def dbus_connection_can_send_type(dbus_connection, type):
    assert isinstance(dbus_connection, DBusConnectionStructure)
    assert isinstance(type, int)
    return dbus.dbus_connection_can_send_type(
        ctypes.pointer(dbus_connection), type)


def dbus_bus_register(dbus_connection):
    assert isinstance(dbus_connection, DBusConnectionStructure)
    error = DBusErrorStructure()
    response = dbus.dbus_bus_register(
        ctypes.pointer(dbus_connection),
        ctypes.pointer(error))
    error.raise_if_set()
    return bool(response)


def dbus_bus_request_name(dbus_connection, name, flags):
    assert isinstance(dbus_connection, DBusConnectionStructure)
    error = DBusErrorStructure()
    response = dbus.dbus_bus_request_name(
        ctypes.pointer(dbus_connection), name, flags, ctypes.pointer(error))
    error.raise_if_set()
    return response


def dbus_connection_set_exit_on_disconnect(
        dbus_connection, exit_on_disconnect):
    assert isinstance(dbus_connection, DBusConnectionStructure)
    assert isinstance(exit_on_disconnect, bool)
    dbus.dbus_connection_set_exit_on_disconnect(
        ctypes.pointer(dbus_connection), exit_on_disconnect)


def dbus_connection_preallocate_send(dbus_connection):
    assert isinstance(dbus_connection, DBusConnectionStructure)
    preallocated = dbus.dbus_connection_preallocate_send(
        ctypes.pointer(dbus_connection))
    if preallocated.contents is None:
        raise Exception()
    return preallocated.contents


def dbus_connection_read_write_dispatch(
        dbus_connection, timeout_milliseconds=1000):
    """ As long as the connection is open, this function will block until
    it can read or write, then read or write, then return TRUE.

    If the connection is closed, the function returns FALSE.

    Also dispatches the messages.
    """
    assert isinstance(dbus_connection, DBusConnectionStructure)
    if timeout_milliseconds is None:
        timeout_milliseconds = -1
    assert isinstance(timeout_milliseconds, int)
    return dbus.dbus_connection_read_write_dispatch(
        ctypes.pointer(dbus_connection),
        timeout_milliseconds) > 0


def dbus_connection_read_write(dbus_connection, timeout_milliseconds=None):
    """ As long as the connection is open, this function will block until
    it can read or write, then read or write, then return TRUE.

    If the connection is closed, the function returns FALSE.
    """
    assert isinstance(dbus_connection, DBusConnectionStructure)
    if timeout_milliseconds is None:
        timeout_milliseconds = -1
    assert isinstance(timeout_milliseconds, int)
    return dbus.dbus_connection_read_write(
        ctypes.pointer(dbus_connection),
        timeout_milliseconds) > 0


def dbus_connection_borrow_message(dbus_connection):
    assert isinstance(dbus_connection, DBusConnectionStructure)
    message = dbus.dbus_connection_borrow_message(
        ctypes.pointer(dbus_connection))
    try:
        return message.contents
    except ValueError as e:
        if 'NULL' in e.message:
            raise IndexError("Empty Queue")
        raise


def dbus_connection_pop_message(dbus_connection):
    assert isinstance(dbus_connection, DBusConnectionStructure)
    message = dbus.dbus_connection_pop_message(
        ctypes.pointer(dbus_connection))
    if message.contents is None:
        raise IndexError("Empty Queue")
    return message.contents


def dbus_connection_return_message(dbus_connection, message):
    assert isinstance(dbus_connection, DBusConnectionStructure)
    assert isinstance(message, DBusMessageStructure)
    dbus.dbus_connection_return_message(
        ctypes.pointer(dbus_connection),
        ctypes.pointer(message))


def dbus_connection_flush(dbus_connection):
    assert isinstance(dbus_connection, DBusConnectionStructure)
    dbus.dbus_connection_flush(ctypes.pointer(dbus_connection))


def dbus_connection_dispatch(dbus_connection):
    assert isinstance(dbus_connection, DBusConnectionStructure)
    return dbus.dbus_connection_dispatch(ctypes.pointer(dbus_connection))


def dbus_connection_register_object_path(
        dbus_connection, path, vtable, user_data
):
    assert isinstance(dbus_connection, DBusConnectionStructure)
    return bool(dbus.dbus_connection_register_object_path(
        ctypes.pointer(dbus_connection),
        path,
        ctypes.pointer(vtable),
        user_data))


class DelBase(object):
    def __del__(self):
        pass


class DBusProxyObject(object):
    @classmethod
    def pytype_to_argspec(cls, pytype):
        if isinstance(pytype, str):
            return 's'
        raise NotImplemented

    def __init__(self, connection, service, path, interface=0):
        self._connection = connection
        self._service = service
        self._path = path
        if isinstance(interface, DBusInterface):
            interface = interface.name
        self._interface = interface

    def dbus_call(self, method_name, *args, **kwargs):
        message = DBusMessage.new_method_call(
            self._service, self._path,
            self._interface, method_name)
        message_iterator = message.get_iterator_for_writing()
        for arg in args:
            message_iterator.append(
                self.pytype_to_argspec(arg), arg)
        response_future = self._connection.send_with_reply(message)
        return response_future


class DBusConnectionMethods(DelBase):
    def __init__(self, *args, **kwargs):
        super(DBusConnectionMethods, self).__init__(*args, **kwargs)
        self._vtable = {}
        self._pending_futures = WeakValueDictionary()

    def fileno(self):
        if not self.is_connected():
            raise ValueError('I/O operation on closed session')
        return self.get_unix_fd()

    def flush(self):
        dbus_connection_flush(self)

    def dispatch(self):
        return dbus_connection_dispatch(self)

    def close(self):
        dbus_connection_close(self)

    def is_connected(self):
        return bool(dbus.dbus_connection_get_is_connected(
            ctypes.pointer(self)))

    def is_authenticated(self):
        return dbus_connection_get_is_authenticated(self)

    def bus_register(self):
        return dbus_bus_register(self)

    def bus_request_name(self, name, flags=0):
        return dbus_bus_request_name(self, name, flags)

    def register_object_path(self, path, vtable, user_data):
        self = self.get_canonical()
        assert isinstance(path, str)
        assert isinstance(vtable, DBusObjectPathVTable)
        registered = bool(dbus_connection_register_object_path(
            self, path, vtable, user_data))
        if not registered:
            return False
        if not hasattr(self, '_vtable'):
            self._vtable = dict()
        self._vtable[path] = vtable

    def try_register_fallback(self, path, vtable, user_data):
        error = DBusErrorStructure()
        dbus.dbus_connection_try_register_fallback(
            ctypes.pointer(self),
            path,
            ctypes.pointer(vtable),
            user_data,
            ctypes.pointer(error))
        error.raise_if_set()
        self._vtable[path] = vtable

    def get_server_id(self):
        return dbus_connection_get_server_id(self)

    def get_socket(self):
        out = ctypes.c_int()
        success = bool(dbus.dbus_connection_get_socket(
            ctypes.pointer(self),
            ctypes.pointer(out)))
        if not success:
            raise Exception('failed')
        return out.value

    def get_unix_fd(self):
        out = ctypes.c_int()
        success = bool(dbus.dbus_connection_get_unix_fd(
            ctypes.pointer(self),
            ctypes.pointer(out)))
        if not success:
            raise Exception('failed')
        return out.value

    def send(self, message):
        assert isinstance(message, DBusMessageStructure)
        out = ctypes.c_uint32()
        is_sent = bool(dbus.dbus_connection_send(
            ctypes.pointer(self),
            ctypes.pointer(message),
            ctypes.pointer(out)))
        if not is_sent:
            raise Exception()
        return out.value

    def send_with_reply(self, message, timeout=DBUS_TIMEOUT_USE_DEFAULT):
        serial = self.send(message)
        future = AsyncResult()
        self._pending_futures[serial] = future
        return future

    def get_object(self, service, path, interface=None):
        return DBusProxyObject(self, service, path, interface=interface)

    def __enter__(self):
        self.get_server_id()
        self.bus_register()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


class DBusMessageStructure(ctypes.Structure):
    """maybe all fields are private"""
    _fields_ = []

    def __init__(self):
        self._allocated = True

    def __del__(self):
        if hasattr(self, '_allocated') and self._allocated:
            dbus.dbus_message_unref(ctypes.pointer(self))


class DBusMessageIterStructure(ctypes.Structure):
    _fields_ = [
        ('dummy1', ctypes.c_void_p),
        ('dummy2', ctypes.c_void_p),
        ('dummy3', ctypes.c_uint32),
        ('dummy4', ctypes.c_int),
        ('dummy5', ctypes.c_int),
        ('dummy6', ctypes.c_int),
        ('dummy7', ctypes.c_int),
        ('dummy8', ctypes.c_int),
        ('dummy9', ctypes.c_int),
        ('dummy10', ctypes.c_int),
        ('dummy11', ctypes.c_int),
        ('pad1', ctypes.c_int),
        ('pad2', ctypes.c_int),
        ('pad3', ctypes.c_void_p)
    ]


class DBusMessageIterIterator(object):
    def __init__(self, parent):
        self._parent = parent

    def __iter__(self):
        return self

    def next(self):
        current_obj = self._parent.current()
        if current_obj is None:
            raise StopIteration()
        self._parent.go_next()
        return current_obj


def _headest(typespec):
    while typespec[0] is not typespec:
        typespec = typespec[0]
    return typespec


class DBusMessageIterMethods(object):
    _type_factory_s = ctypes.c_char_p
    _type_factory_t = ctypes.c_char_p
    _type_factory_d = ctypes.c_double

    def _convert_type_factory(self, factory):
        value = factory()
        dbus.dbus_message_iter_get_basic(
            ctypes.pointer(self),
            ctypes.pointer(value))
        return value.value

    def _convert_type_a(self):
        nested = DBusMessageIter()
        dbus.dbus_message_iter_recurse(
            ctypes.pointer(self),
            ctypes.pointer(nested))
        out_factory = list
        if nested.get_arg_type() == 'e':
            out_factory = dict
        return out_factory(nested)

    def _convert_type_e(self):
        nested = DBusMessageIter()
        dbus.dbus_message_iter_recurse(
            ctypes.pointer(self),
            ctypes.pointer(nested))
        things = list(nested)
        assert len(things) == 2
        return tuple(things)

    def get_arg_type(self):
        dbus_type = dbus.dbus_message_iter_get_arg_type(
            ctypes.pointer(self))
        if dbus_type == DBUS_TYPE_INVALID:
            return None
        return chr(dbus_type)

    def current(self):
        arg_type = self.get_arg_type()
        if arg_type is None:
            return None
        factory_name = '_type_factory_{}'.format(arg_type)
        method_name = '_convert_type_{}'.format(arg_type)
        if hasattr(self, factory_name):
            factory = getattr(self, factory_name)
            return self._convert_type_factory(factory)
        if hasattr(self, method_name):
            return getattr(self, method_name)()
        else:
            raise TypeError('unhandled: {!r}'.format(arg_type))

    def go_next(self):
        return bool(dbus.dbus_message_iter_next(ctypes.pointer(self)))

    def append_basic(self, type_, value):
        success = bool(dbus.dbus_message_iter_append_basic(
            ctypes.pointer(self),
            ord(type_),
            ctypes.pointer(value)
        ))
        if not success:
            raise MemoryError()

    def append(self, typespec_atomised, value):
        contained_signature = None
        if isinstance(typespec_atomised, tuple):
            type_, contained_signature = typespec_atomised
        else:
            type_ = typespec_atomised
        if _headest(type_) in 's':
            return self.append_basic(type_, ctypes.pointer(
                ctypes.create_string_buffer(value.encode('utf8'))))
        elif _headest(type_) == 'a' and contained_signature is not None:
            sub = DBusMessageIter()
            dbus.dbus_message_iter_open_container(
                ctypes.pointer(self), ord('a'), ''.join(contained_signature),
                ctypes.pointer(sub))
            if isinstance(value, dict):
                for pair in value.items():
                    sub.append(''.join(contained_signature), pair)
            dbus.dbus_message_iter_close_container(
                ctypes.pointer(self), ctypes.pointer(sub))
        elif _headest(type_) in 'e':
            sub = DBusMessageIter()
            dbus.dbus_message_iter_open_container(
                ctypes.pointer(self), ord('e'), contained_signature,
                ctypes.pointer(sub))
            sub.append(value[0])
            sub.append(value[1])
            dbus.dbus_message_iter_close_container(
                ctypes.pointer(self), ctypes.pointer(sub))
        else:
            raise Exception('unhandled: %r' % (type_, ))

    def __iter__(self):
        return DBusMessageIterIterator(self)


class DBusMessageIter(DBusMessageIterStructure, DBusMessageIterMethods):
    pass


class DBusMessageMethods(DelBase):

    def get_interface(self):
        return dbus.dbus_message_get_interface(
            ctypes.pointer(self))

    def get_member(self):
        return dbus.dbus_message_get_member(
            ctypes.pointer(self))

    def get_path(self):
        return dbus.dbus_message_get_path(
            ctypes.pointer(self))

    def get_reply_serial(self):
        serial = dbus.dbus_message_get_reply_serial(
            ctypes.pointer(self))
        return None if serial == 0 else serial

    def new_method_return(self):
        return dbus.dbus_message_new_method_return(
            ctypes.pointer(self))

    def get_sender(self):
        return dbus.dbus_message_get_sender(ctypes.pointer(self))

    def is_method_call(self, iface, method):
        return bool(dbus.dbus_message_is_method_call(
            ctypes.pointer(self), iface, method))

    def get_signature(self):
        return dbus.dbus_message_get_signature(ctypes.pointer(self))

    def append_args(self, pairs):
        iterator = DBusMessageIter()
        dbus.dbus_message_iter_init_append(
            ctypes.pointer(self), ctypes.pointer(iterator))
        for type_, value in pairs:
            iterator.append(type_, value)

    def append_object(self, typespec, object):
        typespec_atomised = typespec_atomise(typespec)
        iterator = DBusMessageIter()
        dbus.dbus_message_iter_init_append(
            ctypes.pointer(self), ctypes.pointer(iterator))
        iterator.append(typespec_atomised, object)

    def _inner_repr(self):
        yield 'interface', self.get_interface()
        yield 'member', self.get_member()
        yield 'path', self.get_path()

    def get_iterator(self):
        miter = DBusMessageIter()
        dbus.dbus_message_iter_init(
            ctypes.pointer(self),
            ctypes.pointer(miter))
        return miter

    def iter_args(self):
        return iter(self.get_iterator())

    def get_iterator_for_writing(self):
        miter = DBusMessageIter()
        dbus.dbus_message_iter_init_append(
            ctypes.pointer(self),
            ctypes.pointer(miter))
        return miter


class DBusMessage(DBusMessageStructure, DBusMessageMethods):
    @classmethod
    def new_method_call(cls, destination, path, iface, method):
        dbus.dbus_message_new_method_call.restype = ctypes.POINTER(cls)
        result = dbus.dbus_message_new_method_call(
            destination, path, iface, method).contents
        result._allocated = True
        return result

    def __repr__(self):
        return "{}.{}({})".format(
            type(self).__module__,
            type(self).__name__,
            ', '.join("{0[0]}={0[1]!r}".format(x) for x in self._inner_repr())
        )


class DBusPreallocatedSendStructure(ctypes.Structure):
    """All fields are private"""
    _fields_ = []


class DBusConnectionStructure(ctypes.Structure):
    """All fields are private"""
    _fields_ = []

    def __del__(self):
        if False:
            dbus_connection_unref(ctypes.pointer(self))


class DBusConnection(DBusConnectionMethods, DBusConnectionStructure):
    SESSION = 1
    SYSTEM = 2
    instances = WeakValueDictionary()

    def __new__(cls, bus, address=None, private=False):
        if bus == 'session':
            bus = cls.SESSION
        if bus == 'system':
            bus = cls.SYSTEM
        if address is None and bus == cls.SESSION:
            address = os.environ['DBUS_SESSION_BUS_ADDRESS']
        if private:
            inst = dbus_connection_open_private(address)
        else:
            inst = dbus_connection_open(address)
        if ctypes.addressof(inst) not in cls.instances:
            cls.instances[ctypes.addressof(inst)] = inst
        return inst

    def __init__(self, address, private=False):
        super(DBusConnection, self).__init__()

    def get_canonical(self):
        return self.instances[ctypes.addressof(self)]

    def __repr__(self):
        return '{!s} @ {!s}>'.format(
            super(DBusConnection, self).__repr__()[:-1],
            hex(ctypes.addressof(self)))


DBusObjectPathUnregisterFunction = \
    ctypes.CFUNCTYPE(None, ctypes.POINTER(DBusConnection), ctypes.c_void_p)

DBusObjectPathMessageFunction = \
    ctypes.CFUNCTYPE(
        ctypes.c_int,
        ctypes.POINTER(DBusConnection),
        ctypes.POINTER(DBusMessage),
        ctypes.c_void_p)

padding_func = ctypes.CFUNCTYPE(ctypes.c_void_p)


class DBusObjectPathVTable(ctypes.Structure):
    _fields_ = [
        ('_unregister_function', DBusObjectPathUnregisterFunction),
        ('_message_function', DBusObjectPathMessageFunction),
        ('dbus_internal_pad1', padding_func),
        ('dbus_internal_pad2', padding_func),
        ('dbus_internal_pad3', padding_func),
        ('dbus_internal_pad4', padding_func)
    ]

    def __init__(self):
        self._message_function = DBusObjectPathMessageFunction(
            self.message_function
        )
        self._unregister_function = DBusObjectPathUnregisterFunction(
            self.message_function
        )


class DBusPrivateConnection(DBusConnection):
    def __del__(self):
        self.close()
        super(DBusPrivateConnection, self).__del__()


class DBusErrorStructure(ctypes.Structure):
    _fields_ = [
        ('name', ctypes.c_char_p),
        ('message', ctypes.c_char_p),
        ('dummy1', ctypes.c_uint),
        ('dummy2', ctypes.c_uint),
        ('dummy3', ctypes.c_uint),
        ('dummy4', ctypes.c_uint),
        ('dummy5', ctypes.c_uint),
        ('padding1', ctypes.c_void_p)
    ]

    def is_set(self):
        return dbus.dbus_error_is_set(ctypes.pointer(self)) > 0

    def raise_if_set(self):
        if self.is_set():
            raise DBusError(self)


class DBusPendingCallStructure(ctypes.Structure):
    _fields_ = []


class DBusPendingCallMethods(object):
    pass


class DBusPendingCall(DBusPendingCallStructure, DBusPendingCallMethods):
    pass


class CoolDBusPendingCall(DBusPendingCall):
    def __init__(self, connection):
        self._message = None
        self.connection = connection
        self.connection.add_pending_call(self)
        success = bool(dbus.dbus_pending_call_set_notify(
            ctypes.pointer(self),
            DBusObjectPathMessageFunction(
                self.handle_notify)))
        if not success:
            raise MemoryError()

    def handle_notify(self, user_data):
        self.connection.remove_pending_call(self)
        assert bool(dbus.dbus_pending_call_get_completed(
            ctypes.pointer(self)))
        dbus.dbus_pending_call_steal_reply.restype = \
            ctypes.POINTER(DBusMessage)
        message = dbus.dbus_pending_call_steal_reply(
            ctypes.pointer(self)).contents
        message._allocated = True
        self._message = message

    def __del__(self):
        if hasattr(self, '_allocated') and self._allocated:
            dbus.dbus_pending_call_unref(ctypes.pointer(self))


DBusPendingCallNotifyFunction = \
    ctypes.CFUNCTYPE(ctypes.POINTER(DBusPendingCall), ctypes.c_void_p)


class DBusError(Exception):
    def __init__(self, dbus_exc):
        super(DBusError, self).__init__(dbus_exc.name, dbus_exc.message)
        self.original = dbus_exc


dbus.dbus_connection_ref.restype = \
    ctypes.POINTER(DBusConnection)

dbus.dbus_connection_open.restype = \
    ctypes.POINTER(DBusConnection)

dbus.dbus_connection_open_private.restype = \
    ctypes.POINTER(DBusPrivateConnection)

dbus.dbus_error_is_set.restype = ctypes.c_uint32
dbus.dbus_connection_get_server_id.restype = ctypes.c_char_p

dbus.dbus_connection_borrow_message.restype = \
    ctypes.POINTER(DBusMessage)

dbus.dbus_connection_pop_message.restype = \
    ctypes.POINTER(DBusMessage)

dbus.dbus_bus_get_unique_name.restype = ctypes.c_char_p

dbus.dbus_message_get_serial.restype = ctypes.c_uint32
dbus.dbus_message_get_type.restype = ctypes.c_int
dbus.dbus_message_get_signature.restype = ctypes.c_char_p
dbus.dbus_message_get_interface.restype = ctypes.c_char_p
dbus.dbus_message_get_member.restype = ctypes.c_char_p
dbus.dbus_message_get_path.restype = ctypes.c_char_p
dbus.dbus_message_new_method_return.restype = \
    ctypes.POINTER(DBusMessage)
