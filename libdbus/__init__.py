import weakref
import ctypes

dbus = ctypes.CDLL('libdbus-1.so.3')


DBUS_TYPE_INVALID = 0

DBUS_DISPATCH_DATA_REMAINS = 0
DBUS_DISPATCH_COMPLETE = 1
DBUS_DISPATCH_NEED_MEMORY = 2

DBUS_HANDLER_RESULT_HANDLED = 0
DBUS_HANDLER_RESULT_NOT_YET_HANDLED = 1
DBUS_HANDLER_RESULT_NEED_MEMORY = 2

DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE = \
    '<!DOCTYPE node PUBLIC ' \
    '"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"' \
    '\n"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">\n'


def dbus_error_is_set(dbus_error):
    assert isinstance(dbus_error, DBusErrorStructure)
    return dbus.dbus_error_is_set(ctypes.pointer(dbus_error)) > 0


def dbus_connection_open(dbus_addr):
    error = DBusErrorStructure()
    conn = dbus.dbus_connection_open(dbus_addr, ctypes.pointer(error))
    if dbus.dbus_error_is_set(ctypes.pointer(error)) > 0:
        raise DBusError(error)
    return conn.contents


def dbus_connection_open_private(dbus_addr):
    error = DBusErrorStructure()
    conn = dbus.dbus_connection_open_private(dbus_addr, ctypes.pointer(error))
    if dbus.dbus_error_is_set(ctypes.pointer(error)) > 0:
        raise DBusError(error)
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
    if dbus.dbus_error_is_set(ctypes.pointer(error)) > 0:
        raise DBusError(error)
    return bool(response)


def dbus_bus_request_name(dbus_connection, name, flags):
    assert isinstance(dbus_connection, DBusConnectionStructure)
    error = DBusErrorStructure()
    response = dbus.dbus_bus_request_name(
        ctypes.pointer(dbus_connection), name, flags, ctypes.pointer(error))
    if dbus.dbus_error_is_set(ctypes.pointer(error)) > 0:
        raise DBusError(error)
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
    if message.content is None:
        raise IndexError("Empty Queue")
    return message.context


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


class DBusConnectionMethods(DelBase):
    def fileno(self):
        return self.get_unix_fd()

    def flush(self):
        dbus_connection_flush(self)

    def dispatch(self):
        return dbus_connection_dispatch(self)

    def close(self):
        dbus_connection_close(self)

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


class DBusMessageIterMethods(object):
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
        if arg_type == 's':
            value = ctypes.c_char_p()
            dbus.dbus_message_iter_get_basic(
                ctypes.pointer(self),
                ctypes.pointer(value))
            return value.value
        else:
            raise TypeError('unhandled: {!r}'.format(arg_type))

    def go_next(self):
        return bool(dbus.dbus_message_iter_next(ctypes.pointer(self)))

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

    def _conv_value(self, type_, value, pointer=ctypes.pointer):
        if type_ == 's':
            return pointer(pointer(
                ctypes.create_string_buffer(value.encode('utf8'))))
        else:
            raise TypeError('unhandled')

    def append_args(self, pairs):
        exargs = []
        for type_, value in pairs:
            new_val = self._conv_value(type_, value)
            exargs.append(ord(type_))
            exargs.append(new_val)
        exargs.append(0)
        return dbus.dbus_message_append_args(
            ctypes.pointer(self), *exargs)

    def _inner_repr(self):
        yield 'interface', self.get_interface()
        yield 'member', self.get_member()
        yield 'path', self.get_path()

    def iter_args(self):
        miter = DBusMessageIter()
        dbus.dbus_message_iter_init(
            ctypes.pointer(self),
            ctypes.pointer(miter))
        return iter(miter)


class DBusMessage(DBusMessageStructure, DBusMessageMethods):
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
    instances = weakref.WeakValueDictionary()

    def __init__(self, *args, **kwargs):
        instance = self.instances.get(ctypes.addressof(self), None)
        if instance is None:
            self.instances[ctypes.addressof(self)] = self
        super(DBusConnection, self).__init__(*args, **kwargs)

    def get_canonical(self):
        return self.instances[ctypes.addressof(self)]

    @classmethod
    def open(cls, address):
        return dbus_connection_open(address)

    @classmethod
    def open_private(cls, address):
        conn = dbus_connection_open_private(address)
        DBusConnection.__init__(conn)
        return conn

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


class DBusError(Exception):
    def __init__(self, _dbus_exc):
        super(DBusError, self).__init__(_dbus_exc.name, _dbus_exc.message)
        self.original = _dbus_exc


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
