"""Patch Ryu 4.34 to work with eventlet >= 0.33 on Python 3.10.

Ryu's ryu/app/wsgi.py imports eventlet.wsgi.ALREADY_HANDLED, which newer
eventlet removed in favour of the WSGI_LOCAL.already_handled flag. This
rewrites Ryu's _AlreadyHandledResponse (used only for websockets) to the new
mechanism. Safe to run more than once.
"""
import pathlib
import ryu.app as _app_pkg  # noqa: only to locate the package

path = pathlib.Path(_app_pkg.__file__).with_name("wsgi.py")
src = path.read_text()

OLD = """    # XXX: Eventlet API should not be used directly.
    from eventlet.wsgi import ALREADY_HANDLED
    _ALREADY_HANDLED = ALREADY_HANDLED

    def __call__(self, environ, start_response):
        return self._ALREADY_HANDLED
"""
NEW = """    # Patched for eventlet >= 0.33 (ALREADY_HANDLED was removed).
    def __call__(self, environ, start_response):
        from eventlet.wsgi import WSGI_LOCAL
        WSGI_LOCAL.already_handled = True
        return []
"""

if NEW in src:
    print("already patched:", path)
elif OLD in src:
    path.write_text(src.replace(OLD, NEW))
    print("patched:", path)
else:
    raise SystemExit("unexpected wsgi.py content, patch not applied: %s" % path)
