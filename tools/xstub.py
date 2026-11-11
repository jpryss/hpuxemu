#!/usr/bin/env python3
"""xstub.py - a small X11 server for testing X clients under the emulator where no real
X server is available: speaks the core protocol well enough for Xlib and Xt programs to
start, create windows, load fonts, draw and wait for events, and keeps a framebuffer so
that what they drew can be looked at.

    python3 tools/xstub.py [-r ROOT] [-d N] [-o screen.png] [-t SECONDS] [-v] [--size WxH] [-c CONTROL]

Listens on /tmp/.X11-unix/XN (the emulator passes that path through to the host), one
screen of WxH at depth 24 (TrueColor), the root's own PCF fonts (usr/lib/X11/fonts and
the CDE fonts; run HP's mkfontdir in the emulator first for the fonts.dir files),
writes the framebuffer to the PNG every second and at exit,
and exits after SECONDS (default: never). -v logs every request. It is a test tool,
not an X server: no clipping to windows, no extensions, no authorization; requests it
does not understand are acknowledged and the ones needing a reply get a plausible one.

It does have the event model a window manager and Motif need: per-client event masks,
SubstructureRedirect (MapRequest/ConfigureRequest to the window manager), stacking,
Enter/Leave, focus, passive and active grabs with synchronous pointer modes and
AllowEvents, SendEvent, a Latin-1 keyboard map. Input comes from a control socket
(-c PATH, a Unix socket; tools/xdrive.py talks to it): "move X Y", "press [N]",
"release [N]", "click X Y [N]", "key NAME", "type TEXT", "snap FILE", "windows",
"requests", each answered with one line."""

import os
import select
import signal
import socket
import struct
import sys
import time

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    Image = None

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcffont  # noqa: E402

REQUEST_NAMES = {1: 'CreateWindow', 2: 'ChangeWindowAttributes', 3: 'GetWindowAttributes', 4: 'DestroyWindow',
                 5: 'DestroySubwindows', 6: 'ChangeSaveSet', 7: 'ReparentWindow', 8: 'MapWindow', 9: 'MapSubwindows',
                 10: 'UnmapWindow', 11: 'UnmapSubwindows', 12: 'ConfigureWindow', 13: 'CirculateWindow', 14: 'GetGeometry',
                 15: 'QueryTree', 16: 'InternAtom', 17: 'GetAtomName', 18: 'ChangeProperty', 19: 'DeleteProperty',
                 20: 'GetProperty', 21: 'ListProperties', 22: 'SetSelectionOwner', 23: 'GetSelectionOwner',
                 24: 'ConvertSelection', 25: 'SendEvent', 26: 'GrabPointer', 27: 'UngrabPointer', 28: 'GrabButton',
                 29: 'UngrabButton', 30: 'ChangeActivePointerGrab', 31: 'GrabKeyboard', 32: 'UngrabKeyboard', 33: 'GrabKey',
                 34: 'UngrabKey', 35: 'AllowEvents', 36: 'GrabServer', 37: 'UngrabServer', 38: 'QueryPointer',
                 39: 'GetMotionEvents', 40: 'TranslateCoordinates', 41: 'WarpPointer', 42: 'SetInputFocus',
                 43: 'GetInputFocus', 44: 'QueryKeymap', 45: 'OpenFont', 46: 'CloseFont', 47: 'QueryFont',
                 48: 'QueryTextExtents', 49: 'ListFonts', 50: 'ListFontsWithInfo', 51: 'SetFontPath', 52: 'GetFontPath',
                 53: 'CreatePixmap', 54: 'FreePixmap', 55: 'CreateGC', 56: 'ChangeGC', 57: 'CopyGC', 58: 'SetDashes',
                 59: 'SetClipRectangles', 60: 'FreeGC', 61: 'ClearArea', 62: 'CopyArea', 63: 'CopyPlane', 64: 'PolyPoint',
                 65: 'PolyLine', 66: 'PolySegment', 67: 'PolyRectangle', 68: 'PolyArc', 69: 'FillPoly',
                 70: 'PolyFillRectangle', 71: 'PolyFillArc', 72: 'PutImage', 73: 'GetImage', 74: 'PolyText8',
                 75: 'PolyText16', 76: 'ImageText8', 77: 'ImageText16', 78: 'CreateColormap', 79: 'FreeColormap',
                 80: 'CopyColormapAndFree', 81: 'InstallColormap', 82: 'UninstallColormap', 83: 'ListInstalledColormaps',
                 84: 'AllocColor', 85: 'AllocNamedColor', 86: 'AllocColorCells', 87: 'AllocColorPlanes', 88: 'FreeColors',
                 89: 'StoreColors', 90: 'StoreNamedColor', 91: 'QueryColors', 92: 'LookupColor', 93: 'CreateCursor',
                 94: 'CreateGlyphCursor', 95: 'FreeCursor', 96: 'RecolorCursor', 97: 'QueryBestSize', 98: 'QueryExtension',
                 99: 'ListExtensions', 100: 'ChangeKeyboardMapping', 101: 'GetKeyboardMapping', 102: 'ChangeKeyboardControl',
                 103: 'GetKeyboardControl', 104: 'Bell', 105: 'ChangePointerControl', 106: 'GetPointerControl',
                 107: 'SetScreenSaver', 108: 'GetScreenSaver', 109: 'ChangeHosts', 110: 'ListHosts', 111: 'SetAccessControl',
                 112: 'SetCloseDownMode', 113: 'KillClient', 114: 'RotateProperties', 115: 'ForceScreenSaver',
                 116: 'SetPointerMapping', 117: 'GetPointerMapping', 118: 'SetModifierMapping', 119: 'GetModifierMapping',
                 127: 'NoOperation'}

EVENT_NAMES = {2: 'KeyPress', 3: 'KeyRelease', 4: 'ButtonPress', 5: 'ButtonRelease', 6: 'MotionNotify', 7: 'EnterNotify',
               8: 'LeaveNotify', 9: 'FocusIn', 10: 'FocusOut', 12: 'Expose'}

# requests that have a reply
WITH_REPLY = {3, 14, 15, 16, 17, 20, 21, 23, 26, 31, 38, 39, 40, 43, 44, 47, 48, 49, 50, 52, 73, 83, 84, 85, 86, 87, 91, 92,
              97, 98, 99, 101, 103, 106, 108, 110, 117, 119}

PREDEFINED_ATOMS = ['PRIMARY', 'SECONDARY', 'ARC', 'ATOM', 'BITMAP', 'CARDINAL', 'COLORMAP', 'CURSOR', 'CUT_BUFFER0',
                    'CUT_BUFFER1', 'CUT_BUFFER2', 'CUT_BUFFER3', 'CUT_BUFFER4', 'CUT_BUFFER5', 'CUT_BUFFER6', 'CUT_BUFFER7',
                    'DRAWABLE', 'FONT', 'INTEGER', 'PIXMAP', 'POINT', 'RECTANGLE', 'RESOURCE_MANAGER', 'RGB_COLOR_MAP',
                    'RGB_BEST_MAP', 'RGB_BLUE_MAP', 'RGB_DEFAULT_MAP', 'RGB_GRAY_MAP', 'RGB_GREEN_MAP', 'RGB_RED_MAP',
                    'STRING', 'VISUALID', 'WINDOW', 'WM_COMMAND', 'WM_HINTS', 'WM_CLIENT_MACHINE', 'WM_ICON_NAME',
                    'WM_ICON_SIZE', 'WM_NAME', 'WM_NORMAL_HINTS', 'WM_SIZE_HINTS', 'WM_ZOOM_HINTS', 'MIN_SPACE', 'NORM_SPACE',
                    'MAX_SPACE', 'END_SPACE', 'SUPERSCRIPT_X', 'SUPERSCRIPT_Y', 'SUBSCRIPT_X', 'SUBSCRIPT_Y',
                    'UNDERLINE_POSITION', 'UNDERLINE_THICKNESS', 'STRIKEOUT_ASCENT', 'STRIKEOUT_DESCENT', 'ITALIC_ANGLE',
                    'X_HEIGHT', 'QUAD_WIDTH', 'WEIGHT', 'POINT_SIZE', 'RESOLUTION', 'COPYRIGHT', 'NOTICE', 'FONT_NAME',
                    'FAMILY_NAME', 'FULL_NAME', 'CAP_HEIGHT', 'WM_CLASS', 'WM_TRANSIENT_FOR']

ROOT = 0x100
ROOT_VISUAL = 0x21
ROOT_COLORMAP = 0x20
FONT_W, FONT_ASCENT, FONT_DESCENT = 6, 11, 2

# the X11 colour names a client may look up (a small part of rgb.txt)
COLORS = {'white': (255, 255, 255), 'black': (0, 0, 0), 'red': (255, 0, 0), 'green': (0, 255, 0), 'blue': (0, 0, 255),
          'yellow': (255, 255, 0), 'gray': (190, 190, 190), 'grey': (190, 190, 190), 'navy': (0, 0, 128),
          'lightgray': (211, 211, 211), 'lightgrey': (211, 211, 211), 'darkgray': (169, 169, 169), 'cyan': (0, 255, 255),
          'magenta': (255, 0, 255), 'orange': (255, 165, 0), 'brown': (165, 42, 42), 'wheat': (245, 222, 179),
          'lightblue': (173, 216, 230), 'skyblue': (135, 206, 235), 'pink': (255, 192, 203), 'gold': (255, 215, 0),
          'maroon': (176, 48, 96), 'purple': (160, 32, 240), 'violet': (238, 130, 238), 'turquoise': (64, 224, 208),
          'gray50': (127, 127, 127), 'gray75': (191, 191, 191), 'gray25': (64, 64, 64), 'lightyellow': (255, 255, 224),
          'cadetblue': (95, 158, 160), 'steelblue': (70, 130, 180), 'bisque': (255, 228, 196), 'thistle': (216, 191, 216)}


def pad4(n):
    return (4 - n % 4) % 4


# The keyboard: keycode 8 + i has the keysyms KEYS[i] = (unshifted, shifted). Letters
# share a keycode with their capital, every other printable Latin-1 character has its
# own, then the keys Motif and xterm need by name.
KEYSYM_NAMES = {'Return': 0xFF0D, 'BackSpace': 0xFF08, 'Tab': 0xFF09, 'Escape': 0xFF1B, 'Delete': 0xFFFF, 'Home': 0xFF50,
                'Left': 0xFF51, 'Up': 0xFF52, 'Right': 0xFF53, 'Down': 0xFF54, 'Prior': 0xFF55, 'Next': 0xFF56, 'End': 0xFF57,
                'Insert': 0xFF63, 'Shift_L': 0xFFE1, 'Control_L': 0xFFE3, 'Alt_L': 0xFFE9, 'Meta_L': 0xFFE7, 'space': 0x20,
                'Linefeed': 0xFF0A, 'Menu': 0xFF67, 'Help': 0xFF6A}
KEYSYM_NAMES.update(('F%d' % i, 0xFFBD + i) for i in range(1, 13))
KEYS = []
for _c in range(0x20, 0x7F):
    if chr(_c).isalpha():
        if chr(_c).islower():
            KEYS.append((_c, ord(chr(_c).upper())))
    else:
        KEYS.append((_c, _c))
for _c in range(0xA0, 0x100):
    KEYS.append((_c, _c))
for _n, _k in sorted(KEYSYM_NAMES.items(), key=lambda kv: kv[1]):
    if _k >= 0xFF00:
        KEYS.append((_k, _k))


def keycode_for(keysym):
    for i, (lo, hi) in enumerate(KEYS):
        if keysym in (lo, hi):
            return 8 + i
    return 0


class Client:
    def __init__(self, sock, server):
        self.sock = sock
        self.server = server
        self.buf = b''
        self.seq = 0
        self.bo = '>'
        self.setup_done = False
        self.closed = False

    def send(self, data):
        # a client that stops reading must not stop the server: a few seconds, then
        # the connection is dropped (a real server would buffer and eventually do the same)
        try:
            self.sock.sendall(data)
        except (OSError, socket.timeout):
            self.closed = True

    def reply(self, data1=0, body=b'', extra=b''):
        """a 32-byte reply (body fills bytes 8..32) plus `extra` (padded to 4)"""
        extra += b'\0' * pad4(len(extra))
        body = body.ljust(24, b'\0')[:24]
        self.send(struct.pack(self.bo + 'BBHI', 1, data1 & 0xFF, self.seq & 0xFFFF, len(extra) // 4) + body + extra)

    def event(self, code, detail=0, body=b''):
        self.send(struct.pack(self.bo + 'BBH', code, detail, self.seq & 0xFFFF) + body.ljust(28, b'\0')[:28])

    def error(self, code, value=0, minor=0, major=0):
        self.send(struct.pack(self.bo + 'BBHIHB', 0, code, self.seq & 0xFFFF, value, minor, major) + b'\0' * 21)

    def feed(self, data):
        self.buf += data
        while not self.closed:
            if not self.setup_done:
                if len(self.buf) < 12:
                    return
                self.bo = '>' if self.buf[0:1] == b'B' else '<'
                major, minor, nauth, ndata = struct.unpack(self.bo + 'HHHH', self.buf[2:10])
                total = 12 + nauth + pad4(nauth) + ndata + pad4(ndata)
                if len(self.buf) < total:
                    return
                self.buf = self.buf[total:]
                self.setup_done = True
                self.rid_base = self.server.next_rid_base()
                self.send(self.server.setup_reply(self.bo, self.rid_base))
                continue
            if len(self.buf) < 4:
                return
            opcode, data = self.buf[0], self.buf[1]
            length = struct.unpack(self.bo + 'H', self.buf[2:4])[0] * 4
            if length == 0:
                # BIG-REQUESTS (not advertised, but be safe)
                if len(self.buf) < 8:
                    return
                length = struct.unpack(self.bo + 'I', self.buf[4:8])[0] * 4
            if len(self.buf) < length:
                return
            req = self.buf[:length]
            self.buf = self.buf[length:]
            self.seq += 1
            try:
                self.server.handle(self, opcode, data, req)
            except Exception as e:     # a bug in the stub must not kill the client
                sys.stderr.write('xstub: %s: %s\n' % (REQUEST_NAMES.get(opcode, opcode), e))
                if opcode in WITH_REPLY:
                    self.reply()


class Server:
    def __init__(self, width, height, out, verbose, fontdirs=()):
        self.width, self.height = width, height
        self.fontdir = pcffont.FontDir(fontdirs)
        self.fallback_font = None
        self.out = out
        self.verbose = verbose
        self.atoms = {name: i + 1 for i, name in enumerate(PREDEFINED_ATOMS)}
        self.atom_names = {i + 1: name for i, name in enumerate(PREDEFINED_ATOMS)}
        self.properties = {}      # (window, atom) -> (type, format, data)
        self.windows = {ROOT: dict(parent=0, x=0, y=0, w=width, h=height, mapped=True, bg=0xFFFFFF, bgpix=0, event_mask=0, masks={},
                                   override=False, client=None, img=Image.new('RGB', (width, height), (255, 255, 255)) if Image else None)}
        self.t0 = time.time()
        self.px, self.py = width // 2, height // 2      # the pointer
        self.pointer_win = ROOT
        self.buttons = 0            # Button1Mask ... as in the event state field
        self.modifiers = 0          # Shift 1, Control 4, Mod1 8
        self.focus = 1              # PointerRoot
        self.focus_revert = 1
        self.pgrab = None           # active pointer grab: dict(window, client, owner_events, mask, sync, implicit)
        self.kgrab = None           # active keyboard grab
        self.passive = []           # GrabButton records
        self.frozen = []            # pointer events queued while a synchronous grab holds
        self.gcs = {}             # gc -> dict(fg, bg, font, ...)
        self.pixmaps = {}         # id -> (Image, depth)
        self.fonts = {}           # id -> pcffont.Font
        self.selections = {}
        self.counts = {}
        self.clients = []
        self.first_map_exposed = False
        self.fb = Image.new('RGB', (width, height), (255, 255, 255)) if Image else None
        self.draw = ImageDraw.Draw(self.fb) if self.fb else None
        self.pil_font = ImageFont.load_default() if Image else None
        self.dirty = False

    # ---- setup ----
    def next_rid_base(self):
        """each client gets its own range of resource ids, as a real server gives: with
        one shared base two clients' window ids collide in the stub's tables"""
        self.rid_count = getattr(self, 'rid_count', 0) + 1
        return 0x00200000 * self.rid_count

    def setup_reply(self, bo, rid_base=0x00200000):
        vendor = b'hpuxemu xstub'
        formats = struct.pack('BBB5x', 1, 1, 32) + struct.pack('BBB5x', 8, 8, 32) + struct.pack('BBB5x', 24, 32, 32)
        visual = struct.pack(bo + 'IBBHIII4x', ROOT_VISUAL, 4, 8, 256, 0xFF0000, 0x00FF00, 0x0000FF)
        depth = struct.pack(bo + 'BxH4x', 24, 1) + visual
        depth1 = struct.pack(bo + 'BxH4x', 1, 0)
        screen = struct.pack(bo + 'IIIIIHHHHHHIBBBB', ROOT, ROOT_COLORMAP, 0xFFFFFF, 0, 0, self.width, self.height,
                             self.width * 254 // 960, self.height * 254 // 960, 1, 1, ROOT_VISUAL, 0, 0, 24, 2) + depth + depth1
        body = struct.pack(bo + 'IIIIHHBBBBBBBB4x', 11000000, rid_base, 0x001FFFFF, 256, len(vendor), 65535, 1, 3, 0, 0, 32, 32, 8, 255)
        body += vendor + b'\0' * pad4(len(vendor)) + formats + screen
        return struct.pack(bo + 'BxHHH', 1, 11, 0, len(body) // 4) + body

    # ---- helpers ----
    def atom(self, name):
        if name not in self.atoms:
            n = len(self.atoms) + 1
            self.atoms[name] = n
            self.atom_names[n] = name
        return self.atoms[name]

    def drawable(self, d):
        """(image, draw, xoff, yoff) for a pixmap or a window. Every InputOutput window with
        a background of its own has an image (its backing store) and the offsets are 0;
        an InputOnly window or one whose background is None or ParentRelative has no
        pixels of its own, so what is drawn on it lands on the nearest ancestor that has
        (mwm's frame parts, Motif's drawing areas). The screen is composed from the tree
        in stacking order when it is saved. Drawing on an unviewable window goes nowhere."""
        if d in self.pixmaps:
            img = self.pixmaps[d][0]
            return img, ImageDraw.Draw(img), 0, 0
        if d not in self.windows or not self.viewable(d):
            return None, None, 0, 0
        x = y = 0
        w = self.windows[d]
        while w.get('img') is None and d != ROOT:
            x += w['x']
            y += w['y']
            d = w['parent']
            w = self.windows.get(d)
            if w is None:
                return None, None, 0, 0
        if w.get('img') is None:
            return None, None, 0, 0
        return w['img'], ImageDraw.Draw(w['img']), x, y

    def opaque(self, w):
        return not w.get('inputonly') and (w.get('bg') is not None or w.get('bgpix', 0) not in (0, 1))

    def new_window_image(self, w):
        if Image and self.opaque(w):
            w['img'] = Image.new('RGB', (max(1, w['w']), max(1, w['h'])), (0, 0, 0))
            self.paint_background(w, 0, 0, w['w'], w['h'])
        else:
            w['img'] = None

    def resize_window_image(self, w):
        """a window that changes size keeps what was drawn; the new part gets the background"""
        if not Image or w.get('img') is None:
            return
        size = (max(1, w['w']), max(1, w['h']))
        if w['img'].size != size:
            old = w['img']
            w['img'] = Image.new('RGB', size, (0, 0, 0))
            self.paint_background(w, 0, 0, size[0], size[1])
            w['img'].paste(old, (0, 0))

    def paint_background(self, w, x, y, width, height):
        """the window's background pixel, or its background pixmap tiled, over a rectangle"""
        img = w.get('img')
        if img is None or width <= 0 or height <= 0:
            return
        tile = self.pixmaps.get(w.get('bgpix', 0))
        if tile is not None:
            t = tile[0]
            tw, th = t.size
            for ty in range(y - y % th, y + height, th):
                for tx in range(x - x % tw, x + width, tw):
                    img.paste(t, (tx, ty))
        else:
            ImageDraw.Draw(img).rectangle([x, y, x + width - 1, y + height - 1], fill=self.rgb(w.get('bg') or 0xFFFFFF))
        self.dirty = True

    def compose(self, wid=ROOT, x=0, y=0, clip=None):
        """paint a viewable window's image into the framebuffer, then its children in
        stacking order (dict order, last on top), each clipped to its parent"""
        w = self.windows.get(wid)
        if w is None or not w['mapped']:
            return
        if clip is None:
            clip = (0, 0, self.width, self.height)
        box = (max(clip[0], x), max(clip[1], y), min(clip[2], x + w['w']), min(clip[3], y + w['h']))
        if box[0] >= box[2] or box[1] >= box[3]:
            return
        if wid != ROOT and w.get('img') is not None:
            self.fb.paste(w['img'].crop((box[0] - x, box[1] - y, box[2] - x, box[3] - y)), (box[0], box[1]))
        for k, v in list(self.windows.items()):
            if v['parent'] == wid:
                self.compose(k, x + v['x'], y + v['y'], box)

    def rgb(self, pixel):
        return ((pixel >> 16) & 0xFF, (pixel >> 8) & 0xFF, pixel & 0xFF)

    def gc(self, g):
        return self.gcs.get(g, {'fg': 0, 'bg': 0xFFFFFF, 'font': 0, 'line_width': 0, 'fill_style': 0})

    def update_gc(self, g, mask, values, bo):
        d = self.gcs.setdefault(g, {'fg': 0, 'bg': 0xFFFFFF, 'font': 0, 'line_width': 0, 'fill_style': 0})
        names = ['function', 'plane_mask', 'fg', 'bg', 'line_width', 'line_style', 'cap_style', 'join_style', 'fill_style',
                 'fill_rule', 'tile', 'stipple', 'ts_x', 'ts_y', 'font', 'subwindow_mode', 'graphics_exposures', 'clip_x',
                 'clip_y', 'clip_mask', 'dash_offset', 'dashes', 'arc_mode']
        i = 0
        for bit, name in enumerate(names):
            if mask & (1 << bit):
                if 4 * i + 4 <= len(values):
                    d[name] = struct.unpack(bo + 'I', values[4 * i:4 * i + 4])[0]
                i += 1

    def log(self, client, opcode, text=''):
        name = REQUEST_NAMES.get(opcode, 'op%d' % opcode)
        self.counts[name] = self.counts.get(name, 0) + 1
        if self.verbose:
            sys.stderr.write('xstub: %s %s\n' % (name, text))

    # ---- requests ----
    def handle(self, c, op, data, req):
        bo = c.bo
        u32 = lambda off: struct.unpack(bo + 'I', req[off:off + 4])[0]
        u16 = lambda off: struct.unpack(bo + 'H', req[off:off + 2])[0]
        i16 = lambda off: struct.unpack(bo + 'h', req[off:off + 2])[0]
        self.log(c, op)
        if op == 1:      # CreateWindow
            wid, parent = u32(4), u32(8)
            x, y, w, h = i16(12), i16(14), u16(16), u16(18)
            self.windows[wid] = dict(parent=parent, x=x, y=y, w=w, h=h, mapped=False, bg=None, bgpix=0, event_mask=0, client=c,
                                     masks={}, override=False, inputonly=u16(22) == 2, img=None)
            mask = u32(28)
            vals = req[32:]
            self.window_attributes(c, self.windows[wid], mask, vals, bo)
            self.new_window_image(self.windows[wid])
            if parent in self.windows:
                for cl in self.selectors(self.windows[parent], 0x80000):     # SubstructureNotify: CreateNotify
                    cl.event(16, 0, struct.pack(cl.bo + 'IIhhHHHB', parent, wid, x, y, w, h, 0, self.windows[wid]['override']))
        elif op == 2:    # ChangeWindowAttributes
            wid = u32(4)
            mask = u32(8)
            if wid in self.windows:
                self.window_attributes(c, self.windows[wid], mask, req[12:], bo)
        elif op == 3:    # GetWindowAttributes
            wid = u32(4)
            w = self.windows.get(wid, self.windows[ROOT])
            body = struct.pack(bo + 'IHBBIIBBBBIII', ROOT_VISUAL, 2 if w.get('inputonly') else 1, 0, 0, 0, 0, 0, 1,
                               2 if self.viewable(wid) else (1 if w['mapped'] else 0), w.get('override', False), ROOT_COLORMAP,
                               w['event_mask'], w['masks'].get(c, 0))
            c.reply(24, body[:24], body[24:] + b'\0' * 2)
        elif op == 4:    # DestroyWindow
            self.destroy_window(u32(4))
        elif op in (8, 9):    # MapWindow, MapSubwindows
            wid = u32(4)
            targets = [wid] if op == 8 else [k for k, v in self.windows.items() if v['parent'] == wid]
            for t in targets:
                w = self.windows.get(t)
                if w is None:
                    continue
                # SubstructureRedirect on the parent: the window manager gets a
                # MapRequest and maps the window itself (op 8 from it comes back here)
                wm = [cl for cl in self.selectors(self.windows.get(w['parent'], {}), 0x100000) if cl is not c]
                if wm and not w['override'] and not w['mapped']:
                    wm[0].event(20, 0, struct.pack(wm[0].bo + 'II', w['parent'], t))
                    continue
                self.map_window(c, t)
        elif op == 10:   # UnmapWindow
            self.unmap_window(u32(4))
        elif op == 7:    # ReparentWindow(window, parent, x, y)
            wid, parent = u32(4), u32(8)
            x, y = i16(12), i16(14)
            if wid in self.windows:
                w = self.windows[wid]
                old = w['parent']
                w['parent'], w['x'], w['y'] = parent, x, y
                # a reparented window goes to the top of its new parent's children
                self.windows[wid] = self.windows.pop(wid)
                for cl in self.selectors(w, 0x20000) + self.selectors(self.windows.get(old, {}), 0x80000) + self.selectors(self.windows.get(parent, {}), 0x80000):
                    cl.event(21, 0, struct.pack(cl.bo + 'IIIhhB', wid, wid, parent, x, y, w['override']))   # ReparentNotify
                if w['mapped'] and self.windows.get(parent, {}).get('mapped'):
                    self.map_window(c, wid)
        elif op == 12:   # ConfigureWindow
            wid = u32(4)
            mask = u16(8)
            vals = req[12:]
            if wid in self.windows:
                w = self.windows[wid]
                want = dict(w)
                i = 0
                sibling, stack = 0, None
                for bit, name in enumerate(['x', 'y', 'w', 'h', 'border', 'sibling', 'stack']):
                    if mask & (1 << bit):
                        v = struct.unpack(bo + 'I', vals[4 * i:4 * i + 4])[0]
                        i += 1
                        if name in ('w', 'h'):
                            want[name] = v & 0xFFFF
                        elif name in ('x', 'y'):
                            want[name] = (v & 0xFFFF) if (v & 0xFFFF) < 32768 else (v & 0xFFFF) - 65536
                        elif name == 'sibling':
                            sibling = v
                        elif name == 'stack':
                            stack = v & 0xFF
                wm = [cl for cl in self.selectors(self.windows.get(w['parent'], {}), 0x100000) if cl is not c]
                if wm and not w['override']:
                    # the window manager decides: ConfigureRequest, and it reconfigures
                    wm[0].event(23, stack or 0, struct.pack(wm[0].bo + 'IIIhhHHHH', w['parent'], wid, sibling, want['x'], want['y'],
                                                             want['w'], want['h'], 0, mask))
                else:
                    for name in ('x', 'y', 'w', 'h'):
                        w[name] = want[name]
                    self.resize_window_image(w)
                    if stack is not None:
                        self.restack(wid, stack, sibling)
                    self.dirty = True
                    for cl in self.selectors(w, 0x20000) + self.selectors(self.windows.get(w['parent'], {}), 0x80000):
                        cl.event(22, 0, struct.pack(cl.bo + 'IIIhhHHHB', wid, wid, 0, w['x'], w['y'], w['w'], w['h'], 0, w['override']))
        elif op == 14:   # GetGeometry
            d = u32(4)
            if d in self.pixmaps:
                img, depth = self.pixmaps[d]
                body = struct.pack(bo + 'IhhHHH', ROOT, 0, 0, img.size[0], img.size[1], 0)
                c.reply(depth, body)
            else:
                w = self.windows.get(d, self.windows[ROOT])
                c.reply(24, struct.pack(bo + 'IhhHHH', ROOT, w['x'], w['y'], w['w'], w['h'], 0))
        elif op == 15:   # QueryTree
            wid = u32(4)
            kids = [k for k, v in self.windows.items() if v['parent'] == wid]
            c.reply(0, struct.pack(bo + 'IIH', ROOT, self.windows.get(wid, {}).get('parent', 0), len(kids)), b''.join(struct.pack(bo + 'I', k) for k in kids))
        elif op == 16:   # InternAtom
            n = u16(4)
            name = req[8:8 + n].decode('latin1')
            only = data
            if self.verbose:
                sys.stderr.write('xstub:   atom %s\n' % name)
            if only and name not in self.atoms:
                c.reply(0, struct.pack(bo + 'I', 0))
            else:
                c.reply(0, struct.pack(bo + 'I', self.atom(name)))
        elif op == 17:   # GetAtomName
            name = self.atom_names.get(u32(4), '').encode('latin1')
            c.reply(0, struct.pack(bo + 'H', len(name)), name)
        elif op == 18:   # ChangeProperty
            wid, prop, typ = u32(4), u32(8), u32(12)
            fmt = req[16]
            n = u32(20)
            size = n * (fmt // 8)
            if data in (1, 2) and (wid, prop) in self.properties:    # PropModePrepend / Append
                old = self.properties[(wid, prop)][2]
                self.properties[(wid, prop)] = (typ, fmt, old + req[24:24 + size] if data == 2 else req[24:24 + size] + old)
            else:
                self.properties[(wid, prop)] = (typ, fmt, req[24:24 + size])
            if self.verbose:
                sys.stderr.write('xstub:   property %s on %#x = %r\n' % (self.atom_names.get(prop, prop), wid, req[24:24 + min(size, 60)]))
            self.property_notify(wid, prop, 0)
        elif op == 19:
            if self.properties.pop((u32(4), u32(8)), None) is not None:
                self.property_notify(u32(4), u32(8), 1)
        elif op == 20:   # GetProperty
            wid, prop, typ = u32(4), u32(8), u32(12)
            off, ln = u32(16) * 4, u32(20) * 4
            rec = self.properties.get((wid, prop))
            if self.verbose:
                sys.stderr.write('xstub:   get %s on %#x -> %s\n' % (self.atom_names.get(prop, prop), wid, 'none' if rec is None else '%d bytes' % len(rec[2])))
            if rec is None:
                c.reply(0, struct.pack(bo + 'III', 0, 0, 0))
            else:
                ptype, fmt, pdata = rec
                chunk = pdata[off:off + ln]
                after = max(0, len(pdata) - off - len(chunk))
                c.reply(fmt, struct.pack(bo + 'III', ptype, after, len(chunk) // max(1, fmt // 8)), chunk)
                if data and after == 0 and (typ == 0 or typ == ptype):     # delete: the whole value was read
                    self.properties.pop((wid, prop), None)
                    self.property_notify(wid, prop, 1)
        elif op == 21:
            wid = u32(4)
            props = [p for (w, p) in self.properties if w == wid]
            c.reply(0, struct.pack(bo + 'H', len(props)), b''.join(struct.pack(bo + 'I', p) for p in props))
        elif op == 22:
            self.selections[u32(8)] = u32(4)
        elif op == 23:
            c.reply(0, struct.pack(bo + 'I', self.selections.get(u32(4), 0)))
        elif op == 24:   # ConvertSelection: nobody owns anything -> SelectionNotify with no property
            requestor, selection, target, prop, t = u32(4), u32(8), u32(12), u32(16), u32(20)
            c.event(31, 0, struct.pack(bo + 'IIIII', t, requestor, selection, target, 0))
        elif op == 25:   # SendEvent(propagate, destination, event-mask, event)
            dest, emask = u32(4), u32(8)
            ev = bytearray(req[12:44])
            if dest == 0:
                dest = self.pointer_win
            elif dest == 1:
                dest = self.focus_window()
            w = self.windows.get(dest)
            if w is not None:
                targets = self.selectors(w, emask) if emask else ([w['client']] if w['client'] else [])
                if not targets and w['client']:
                    targets = [w['client']]
                for cl in targets:
                    ev[0] |= 0x80
                    ev[2:4] = struct.pack(cl.bo + 'H', cl.seq & 0xFFFF)
                    cl.send(bytes(ev))
        elif op == 26:   # GrabPointer(owner-events, window, event-mask, pointer-mode, keyboard-mode, confine, cursor, time)
            wid = u32(4)
            if self.pgrab and self.pgrab['client'] is not c and not self.pgrab.get('implicit'):
                c.reply(1)      # AlreadyGrabbed
            else:
                self.pgrab = dict(window=wid, client=c, owner_events=bool(data), mask=u16(8), sync=req[10] == 0, frozen=req[10] == 0,
                                  implicit=False)
                c.reply(0)
        elif op == 27:   # UngrabPointer
            if self.pgrab and self.pgrab['client'] is c:
                self.pgrab = None
                self.unfreeze()
        elif op == 28:   # GrabButton(owner-events, window, event-mask, pointer-mode, keyboard-mode, confine, cursor, button, modifiers)
            self.passive.append(dict(window=u32(4), client=c, owner_events=bool(data), mask=u16(8), sync=req[10] == 0,
                                     button=req[20], modifiers=u16(22)))
        elif op == 29:   # UngrabButton(button, window, modifiers)
            self.passive = [g for g in self.passive if not (g['window'] == u32(4) and g['client'] is c and (data == 0 or g['button'] == data))]
        elif op == 31:   # GrabKeyboard(owner-events, window, time, pointer-mode, keyboard-mode)
            self.kgrab = dict(window=u32(4), client=c, owner_events=bool(data))
            c.reply(0)
        elif op == 32:   # UngrabKeyboard
            if self.kgrab and self.kgrab['client'] is c:
                self.kgrab = None
        elif op == 35:   # AllowEvents(mode, time)
            self.allow_events(c, data)
        elif op == 38:   # QueryPointer
            w = self.windows.get(u32(4), self.windows[ROOT])
            ox, oy = self.abs_pos(u32(4))
            c.reply(1, struct.pack(bo + 'IIhhhhH', ROOT, self.child_toward(u32(4), self.pointer_win), self.px, self.py,
                                   self.px - ox, self.py - oy, self.buttons | self.modifiers))
        elif op == 41:   # WarpPointer(src, dst, src-x, src-y, src-w, src-h, dst-x, dst-y)
            dst = u32(8)
            if dst:
                ox, oy = self.abs_pos(dst)
                self.move_pointer(ox + i16(20), oy + i16(22))
            else:
                self.move_pointer(self.px + i16(20), self.py + i16(22))
        elif op == 42:   # SetInputFocus(revert-to, focus, time)
            self.set_focus(u32(4), data)
        elif op == 39:
            c.reply(0, struct.pack(bo + 'I', 0))
        elif op == 40:   # TranslateCoordinates
            src, dst = u32(4), u32(8)
            x, y = i16(12), i16(14)
            sx, sy = self.abs_pos(src)
            dx, dy = self.abs_pos(dst)
            c.reply(1, struct.pack(bo + 'Ihh', self.child_toward(dst, self.window_at(x + sx, y + sy)), x + sx - dx, y + sy - dy))
        elif op == 43:   # GetInputFocus
            c.reply(self.focus_revert, struct.pack(bo + 'I', self.focus))
        elif op == 44:
            c.reply(0, b'', b'\0' * 32)
        elif op == 45:   # OpenFont
            fid = u32(4)
            n = u16(8)
            name = req[12:12 + n].decode('latin1')
            font = self.font_by_name(name)
            self.log(c, op, '%s -> %s' % (name, font.name if font else 'BadName'))
            if font is None:
                c.error(7, fid, 0, op)      # BadName
            else:
                self.fonts[fid] = font
        elif op == 46:
            self.fonts.pop(u32(4), None)
        elif op == 47:   # QueryFont
            font = self.fonts.get(u32(4)) or self.font_by_name('fixed')
            info = self.font_info(bo, font)
            c.reply(0, info[:24], info[24:] + self.font_chars(bo, font))
        elif op == 48:   # QueryTextExtents
            font = self.fonts.get(u32(4)) or self.font_by_name('fixed')
            odd = data
            text = req[8:]
            if odd:
                text = text[:-2]
            # 2-byte characters
            chars = [(text[i] << 8) | text[i + 1] for i in range(0, len(text) - 1, 2)]
            w = sum((font.glyphs.get(ch) or font.glyphs.get(font.default_char) or (0, 0, 0, 0, 0, []))[2] for ch in chars) if font else 0
            c.reply(0, struct.pack(bo + 'hhhhiii', font.ascent, font.descent, font.ascent, font.descent, w, 0, w))
        elif op in (49, 50):     # ListFonts, ListFontsWithInfo
            maxnames = u16(4)
            n = u16(6)
            pattern = req[8:8 + n].decode('latin1')
            matches = self.fontdir.match(pattern, maxnames)
            self.log(c, op, '%s -> %d' % (pattern, len(matches)))
            if op == 49:
                c.reply(0, struct.pack(bo + 'H', len(matches)), b''.join(bytes([len(x)]) + x.encode('latin1') for x in matches))
            else:
                for x in matches[:20]:
                    font = self.fontdir.open(x)
                    if not font:
                        continue
                    info = self.font_info(bo, font)
                    c.reply(len(x), info[:24], info[24:] + struct.pack(bo + 'I', 0) + x.encode('latin1'))
                c.reply(0, b'', b'')
        elif op == 52:
            c.reply(0, struct.pack(bo + 'H', 0))
        elif op == 53:   # CreatePixmap
            pid = u32(4)
            w, h = u16(12), u16(14)
            self.pixmaps[pid] = (Image.new('RGB', (max(w, 1), max(h, 1)), (255, 255, 255)) if Image else None, data)
        elif op == 54:
            self.pixmaps.pop(u32(4), None)
        elif op == 55:   # CreateGC
            g = u32(4)
            self.gcs[g] = {'fg': 0, 'bg': 0xFFFFFF, 'font': 0, 'line_width': 0, 'fill_style': 0}
            self.update_gc(g, u32(12), req[16:], bo)
        elif op == 56:
            self.update_gc(u32(4), u32(8), req[12:], bo)
        elif op == 57:   # CopyGC
            src, dst = u32(4), u32(8)
            self.gcs[dst] = dict(self.gc(src))
        elif op == 60:
            self.gcs.pop(u32(4), None)
        elif op == 61:   # ClearArea
            wid = u32(4)
            x, y, w, h = i16(8), i16(10), u16(12), u16(14)
            if wid in self.windows and self.draw:
                win = self.windows[wid]
                img, dr, ox, oy = self.drawable(wid)
                w = w or win['w'] - x
                h = h or win['h'] - y
                if dr:
                    if win.get('img') is not None:
                        self.paint_background(win, x, y, w, h)
                    self.dirty = True
                    if data:     # exposures: the window redraws the area
                        for cl in self.selectors(win, 0x8000):
                            cl.event(12, 0, struct.pack(cl.bo + 'IHHHHH', wid, max(0, x), max(0, y), w, h, 0))
        elif op == 62:   # CopyArea
            src, dst = u32(4), u32(8)
            sx, sy, dx, dy, w, h = i16(16), i16(18), i16(20), i16(22), u16(24), u16(26)
            simg, _, sox, soy = self.drawable(src)
            dimg, _, dox, doy = self.drawable(dst)
            if self.draw and simg is not None and dimg is not None:
                region = simg.crop((sox + sx, soy + sy, sox + sx + w, soy + sy + h))
                dimg.paste(region, (dox + dx, doy + dy))
                self.dirty = True
        elif op in (64, 65, 66, 67, 68, 69, 70, 71):
            self.poly(c, op, data, req)
        elif op == 72:   # PutImage
            self.put_image(c, data, req)
        elif op == 73:   # GetImage
            d = u32(4)
            x, y, w, h = i16(8), i16(10), u16(12), u16(14)
            if d in self.windows and self.fb is not None:
                self.fb.paste(self.windows[ROOT]['img'], (0, 0))
                self.compose()
                img, ox, oy = self.fb, self.abs_pos(d)[0], self.abs_pos(d)[1]
            else:
                img, _, ox, oy = self.drawable(d)
            out = bytearray()
            if img:
                region = img.crop((ox + x, oy + y, ox + x + w, oy + y + h)).convert('RGB')
                for py in range(h):
                    for px in range(w):
                        r, g, b = region.getpixel((px, py))
                        out += struct.pack('<I', (r << 16) | (g << 8) | b)     # image byte order: LSBFirst
            c.reply(24, struct.pack(bo + 'I', ROOT_VISUAL), bytes(out))
        elif op in (74, 75):     # PolyText8/16
            self.poly_text(c, op, req)
        elif op in (76, 77):     # ImageText8/16
            d, g = u32(4), u32(8)
            x, y = i16(12), i16(14)
            n = data
            text = req[16:16 + (n if op == 76 else 2 * n)]
            self.text(d, g, x, y, text, image=True, wide=(op == 77))
        elif op == 78:
            pass
        elif op == 83:
            c.reply(0, struct.pack(bo + 'H', 1), struct.pack(bo + 'I', ROOT_COLORMAP))
        elif op == 84:   # AllocColor
            r, g, b = u16(8), u16(10), u16(12)
            c.reply(0, struct.pack(bo + 'HHHxxI', r, g, b, ((r >> 8) << 16) | ((g >> 8) << 8) | (b >> 8)))
        elif op == 85:   # AllocNamedColor
            n = u16(8)
            name = req[12:12 + n].decode('latin1').lower().replace(' ', '')
            r, g, b = COLORS.get(name, (0, 0, 0))
            c.reply(0, struct.pack(bo + 'IHHHHHH', (r << 16) | (g << 8) | b, r * 257, g * 257, b * 257, r * 257, g * 257, b * 257))
        elif op == 86:   # AllocColorCells
            ncolors, nplanes = u16(8), u16(10)
            pixels = b''.join(struct.pack(bo + 'I', 0x010101 * (i + 1)) for i in range(ncolors))
            c.reply(0, struct.pack(bo + 'HH', ncolors, nplanes), pixels + b''.join(struct.pack(bo + 'I', 1 << (i + 1)) for i in range(nplanes)))
        elif op == 87:
            c.reply(0, struct.pack(bo + 'HxxIII', u16(8), 0, 0, 0), b''.join(struct.pack(bo + 'I', i + 1) for i in range(u16(8))))
        elif op == 91:   # QueryColors
            n = (len(req) - 8) // 4
            out = b''
            for i in range(n):
                p = u32(8 + 4 * i)
                r, g, b = self.rgb(p)
                out += struct.pack(bo + 'HHHxx', r * 257, g * 257, b * 257)
            c.reply(0, struct.pack(bo + 'H', n), out)
        elif op == 92:   # LookupColor
            n = u16(8)
            name = req[12:12 + n].decode('latin1').lower().replace(' ', '')
            if name in COLORS:
                r, g, b = COLORS[name]
                c.reply(0, struct.pack(bo + 'HHHHHH', r * 257, g * 257, b * 257, r * 257, g * 257, b * 257))
            else:
                c.error(15, 0, 0, op)      # BadName (12 is BadColor, which Xlib does not forgive)
        elif op == 97:   # QueryBestSize
            c.reply(0, struct.pack(bo + 'HH', 16, 16))
        elif op == 98:   # QueryExtension: none
            c.reply(0, struct.pack(bo + 'BBBB', 0, 0, 0, 0))
        elif op == 99:
            c.reply(0, b'', b'')
        elif op == 101:  # GetKeyboardMapping(first, count): 2 keysyms per keycode, from KEYS
            first, count = req[4], req[5]
            out = b''
            for k in range(first, first + count):
                lo, hi = KEYS[k - 8] if 0 <= k - 8 < len(KEYS) else (0, 0)
                out += struct.pack(bo + 'II', lo, hi)
            c.reply(2, b'', out)
        elif op == 103:
            c.reply(0, struct.pack(bo + 'IBBHH', 0, 1, 50, 400, 100), b'\0' * 32)
        elif op == 106:
            c.reply(0, struct.pack(bo + 'HHH', 2, 1, 4))
        elif op == 108:
            c.reply(0, struct.pack(bo + 'HHBB', 600, 600, 0, 0))
        elif op == 110:
            c.reply(1, struct.pack(bo + 'H', 0))
        elif op == 117:
            c.reply(3, b'', b'\x01\x02\x03\0')
        elif op == 118:  # SetModifierMapping: Success (the map itself stays as it is)
            c.reply(0)
        elif op == 119:  # GetModifierMapping: 2 keycodes per modifier; Shift, Lock, Control, Mod1..Mod5
            mods = [keycode_for(0xFFE1), 0, 0, 0, keycode_for(0xFFE3), 0, keycode_for(0xFFE9), 0] + [0] * 8
            c.reply(2, b'', bytes(mods))
        elif op in WITH_REPLY:
            c.reply()
        # everything else is accepted silently

    # ---- the event model ----
    def window_attributes(self, c, w, mask, vals, bo):
        """CreateWindow/ChangeWindowAttributes value list: override-redirect (bit 9) and
        this client's event mask (bit 11)"""
        i = 0
        for bit in range(15):
            if not mask & (1 << bit):
                continue
            if 4 * i + 4 > len(vals):
                break
            v = struct.unpack(bo + 'I', vals[4 * i:4 * i + 4])[0]
            i += 1
            if bit == 0:         # background pixmap: None (0), ParentRelative (1) or a pixmap
                w['bgpix'] = v
                if v not in (0, 1):
                    w['bg'] = None
            elif bit == 1:       # background pixel
                w['bg'] = v
                w['bgpix'] = 0
            elif bit == 9:
                w['override'] = bool(v & 0xFF)
            elif bit == 11:
                w['masks'][c] = v
                w['event_mask'] = 0
                for m in w['masks'].values():
                    w['event_mask'] |= m
        if 'img' in w and w['img'] is None and self.opaque(w):
            self.new_window_image(w)      # a background given after creation

    def property_notify(self, wid, prop, state):
        """PropertyNotify (state 0 NewValue, 1 Deleted) to the clients that selected
        PropertyChange on the window: dtsession waits for each client's WM_COMMAND to
        change after WM_SAVE_YOURSELF, and without the event every client costs it its
        saveYourselfTimeout at logout"""
        w = self.windows.get(wid)
        if w is None:
            return
        for cl in self.selectors(w, 0x400000):
            cl.event(28, 0, struct.pack(cl.bo + 'IIIB', wid, prop, self.now(), state))

    def selectors(self, w, mask):
        """the live clients that selected any of `mask` on window w"""
        return [cl for cl, m in w.get('masks', {}).items() if m & mask and not cl.closed]

    def viewable(self, wid):
        while wid in self.windows and wid != ROOT:
            if not self.windows[wid]['mapped']:
                return False
            wid = self.windows[wid]['parent']
        return wid == ROOT

    def abs_pos(self, wid):
        x = y = 0
        while wid in self.windows and wid != ROOT:
            x += self.windows[wid]['x']
            y += self.windows[wid]['y']
            wid = self.windows[wid]['parent']
        return x, y

    def is_ancestor(self, a, b):
        """a is b or an ancestor of b"""
        while b in self.windows:
            if a == b:
                return True
            if b == ROOT:
                return False
            b = self.windows[b]['parent']
        return False

    def child_toward(self, a, b):
        """the child of a on the way to b (0 if b is not below a)"""
        prev = 0
        while b in self.windows and b != a:
            prev = b
            if b == ROOT:
                return 0
            b = self.windows[b]['parent']
        return prev if b == a else 0

    def restack(self, wid, mode, sibling=0):
        """Above (0) and Below (1): dict order is the stacking order, last on top"""
        w = self.windows.pop(wid)
        if mode == 1 and not sibling:
            items = list(self.windows.items())
            self.windows = dict(items[:1] + [(wid, w)] + items[1:])
        elif sibling in self.windows:
            items = list(self.windows.items())
            i = [k for k, _ in items].index(sibling)
            items.insert(i + 1 if mode == 0 else i, (wid, w))
            self.windows = dict(items)
        else:
            self.windows[wid] = w

    def window_at(self, x, y):
        """the deepest viewable window containing the root point (x, y)"""
        wid = ROOT
        while True:
            found = None
            ox, oy = self.abs_pos(wid)
            for k in reversed(list(self.windows)):
                v = self.windows[k]
                if v['parent'] == wid and v['mapped'] and ox + v['x'] <= x < ox + v['x'] + v['w'] and oy + v['y'] <= y < oy + v['y'] + v['h']:
                    found = k
                    break
            if found is None:
                return wid
            wid = found

    def now(self):
        return int((time.time() - self.t0) * 1000) & 0xFFFFFFFF

    def input_event(self, cl, code, detail, win, child, state):
        ox, oy = self.abs_pos(win)
        if self.verbose:
            sys.stderr.write('xstub:   -> %s %d to %#x (child %#x) at %d,%d state %#x\n' % (EVENT_NAMES.get(code, code), detail, win, child, self.px - ox, self.py - oy, state))
        cl.event(code, detail, struct.pack(cl.bo + 'IIIIhhhhHB', self.now(), ROOT, win, child, self.px, self.py,
                                           self.px - ox, self.py - oy, state, 1))

    def propagate(self, start, mask, code, detail, state, grab_window=None, only_client=None):
        """deliver a device event starting at window `start`, going up until a window
        has a client selecting `mask` (the X propagation rule)"""
        w = start
        while w in self.windows:
            cls = self.selectors(self.windows[w], mask)
            if only_client is not None:
                cls = [cl for cl in cls if cl is only_client]
            if cls:
                for cl in cls:
                    self.input_event(cl, code, detail, w, self.child_toward(w, start), state)
                return w, cls
            if w == ROOT:
                break
            w = self.windows[w]['parent']
        return None, []

    def crossing(self, code, wid, detail, state):
        # the event's focus flag: the window is the focus window or an inferior of it
        # (always, with PointerRoot focus) - Xt decides from it whether the widget under
        # the pointer may take keys, so a wrong flag makes a Motif text field deaf
        f = self.focus
        focus = f in (0, 1) or self.is_ancestor(f, wid)
        for cl in self.selectors(self.windows.get(wid, {}), 0x10 if code == 7 else 0x20):
            ox, oy = self.abs_pos(wid)
            if self.verbose:
                sys.stderr.write('xstub:   -> %s %#x detail %d focus %d\n' % ('EnterNotify' if code == 7 else 'LeaveNotify', wid, detail, focus))
            cl.event(code, detail, struct.pack(cl.bo + 'IIIIhhhhHBB', self.now(), ROOT, wid, 0, self.px, self.py, self.px - ox, self.py - oy, state, 0, 2 | (1 if focus else 0)))

    def pointer_moved(self):
        """the pointer is in another window: LeaveNotify up from the old window to the
        common ancestor (NotifyVirtual on the way), EnterNotify down to the new one -
        the X crossing rules, which a focus-follows-pointer window manager relies on
        (dtwm sets the focus when the pointer enters a *frame*, an ancestor of the
        client window the pointer is actually in)"""
        new = self.window_at(self.px, self.py)
        if new == self.pointer_win:
            return
        old = self.pointer_win
        self.pointer_win = new
        state = self.buttons | self.modifiers
        ANCESTOR, VIRTUAL, INFERIOR, NONLINEAR, NONLINEAR_VIRTUAL = 0, 1, 2, 3, 4
        old_anc = self.ancestors(old) if old in self.windows else []
        new_anc = self.ancestors(new) if new in self.windows else []
        if new in old_anc:          # moved up to an ancestor
            self.crossing(8, old, ANCESTOR, state)
            for a in old_anc:
                if a == new:
                    break
                self.crossing(8, a, VIRTUAL, state)
            self.crossing(7, new, INFERIOR, state)
        elif old in new_anc:        # moved down into a descendant
            self.crossing(8, old, INFERIOR, state)
            path = []
            for a in new_anc:
                if a == old:
                    break
                path.append(a)
            for a in reversed(path):
                self.crossing(7, a, VIRTUAL, state)
            self.crossing(7, new, ANCESTOR, state)
        else:                       # nonlinear: up to the common ancestor, then down
            common = next((a for a in old_anc if a in new_anc), ROOT)
            if old in self.windows:
                self.crossing(8, old, NONLINEAR, state)
                for a in old_anc:
                    if a == common:
                        break
                    self.crossing(8, a, NONLINEAR_VIRTUAL, state)
            path = []
            for a in new_anc:
                if a == common:
                    break
                path.append(a)
            for a in reversed(path):
                self.crossing(7, a, NONLINEAR_VIRTUAL, state)
            self.crossing(7, new, NONLINEAR, state)

    def move_pointer(self, x, y):
        self.px = max(0, min(self.width - 1, x))
        self.py = max(0, min(self.height - 1, y))
        self.pointer_moved()
        state = self.buttons | self.modifiers
        motion_mask = 0x40 | (0x2000 if self.buttons else 0) | (0x100 if self.buttons & 0x100 else 0) | (0x200 if self.buttons & 0x200 else 0) | (0x400 if self.buttons & 0x400 else 0)
        if self.pgrab:
            g = self.pgrab
            if g.get('frozen'):
                self.frozen.append(('move', x, y))
                return
            if g['mask'] & motion_mask or g.get('implicit'):
                if g['owner_events']:
                    w, cls = self.propagate(self.pointer_win, motion_mask, 6, 0, state, only_client=g['client'])
                    if cls:
                        return
                self.input_event(g['client'], 6, 0, g['window'], self.child_toward(g['window'], self.pointer_win), state)
            return
        self.propagate(self.pointer_win, motion_mask, 6, 0, state)

    def press(self, button=1):
        bit = 0x80 << button
        state = self.buttons | self.modifiers        # the state *before* the press
        self.buttons |= bit
        if self.pgrab and not self.pgrab.get('implicit'):
            g = self.pgrab
            if g.get('frozen'):
                self.frozen.append(('press', button))
                return
            self.deliver_to_grab(g, 4, button, state)
            if g['sync']:
                g['frozen'] = True      # SyncPointer: reported, then frozen again
            return
        # passive grabs: the one closest to the root whose window contains the pointer
        chain = []
        w = self.pointer_win
        while w in self.windows:
            chain.append(w)
            if w == ROOT:
                break
            w = self.windows[w]['parent']
        mods = self.modifiers & 0xFF
        for wid in reversed(chain):
            for g in self.passive:
                if g['window'] == wid and g['button'] in (0, button) and g['modifiers'] in (0x8000, mods) and not g['client'].closed:
                    self.pgrab = dict(window=wid, client=g['client'], owner_events=g['owner_events'], mask=g['mask'], sync=g['sync'],
                                      frozen=False, implicit=False, press=(button, state))
                    if self.verbose:
                        sys.stderr.write('xstub:   passive grab on %#x: mask %#x owner_events %s sync %s (pointer in %#x)\n' % (wid, g['mask'], g['owner_events'], g['sync'], self.pointer_win))
                    self.deliver_to_grab(self.pgrab, 4, button, state, trigger=True)
                    if g['sync']:
                        self.pgrab['frozen'] = True
                    return
        w, cls = self.propagate(self.pointer_win, 4, 4, button, state)
        if w is not None:
            # the implicit grab until the buttons are released
            self.pgrab = dict(window=w, client=cls[0], owner_events=True, mask=0x6C | 0x2000, sync=False, implicit=True)

    def deliver_to_grab(self, g, code, button, state, trigger=False):
        if g['owner_events']:
            w, cls = self.propagate(self.pointer_win, 4 if code == 4 else 8, code, button, state, only_client=g['client'])
            if cls:
                return
        # the press that activates a passive grab is always reported (GrabButton's
        # definition); what follows is subject to the grab's event mask
        if trigger or g['mask'] & (4 if code == 4 else 8) or g.get('implicit'):
            self.input_event(g['client'], code, button, g['window'], self.child_toward(g['window'], self.pointer_win), state)

    def release(self, button=1):
        bit = 0x80 << button
        state = self.buttons | self.modifiers
        self.buttons &= ~bit
        if self.pgrab:
            g = self.pgrab
            if g.get('frozen'):
                self.frozen.append(('release', button))
                return
            self.deliver_to_grab(g, 5, button, state)
            if g['sync']:
                g['frozen'] = True
            if not self.buttons and (g.get('implicit') or g.get('press')):
                self.pgrab = None
                self.pointer_moved()
            return
        self.propagate(self.pointer_win, 8, 5, button, state)

    def allow_events(self, c, mode):
        """AllowEvents: ReplayPointer (2) re-delivers the press as if the grab were not
        there; the other pointer modes thaw the grab; keyboard modes are accepted"""
        g = self.pgrab
        if g is None or g['client'] is not c:
            return
        if mode == 2:        # ReplayPointer
            button, state = g.get('press', (1, 0))
            self.pgrab = None
            queued, self.frozen = self.frozen, []
            self.buttons &= ~(0x80 << button)
            saved = self.passive
            self.passive = [p for p in self.passive if p['client'] is not c]
            self.press(button)
            self.passive = saved
            for ev in queued:
                self.replay(ev)
        elif mode in (0, 1, 3, 6):     # AsyncPointer, SyncPointer, AsyncBoth, SyncBoth
            g['sync'] = mode in (1, 6)
            g['frozen'] = False
            self.unfreeze()

    def unfreeze(self):
        queued, self.frozen = self.frozen, []
        for ev in queued:
            self.replay(ev)

    def replay(self, ev):
        if ev[0] == 'move':
            self.move_pointer(ev[1], ev[2])
        elif ev[0] == 'press':
            self.press(ev[1])
        elif ev[0] == 'release':
            self.release(ev[1])

    def focus_window(self):
        if self.focus in (0, 1):
            return self.pointer_win
        return self.focus if self.focus in self.windows else self.pointer_win

    def focus_event(self, code, wid, detail):
        for cl in self.selectors(self.windows.get(wid, {}), 0x200000):
            if self.verbose:
                sys.stderr.write('xstub:   -> %s %#x detail %d\n' % ('FocusIn' if code == 9 else 'FocusOut', wid, detail))
            cl.event(code, detail, struct.pack(cl.bo + 'IB', wid, 0))

    def ancestors(self, wid):
        """the windows above wid, nearest first, up to and including the root"""
        out = []
        while wid in self.windows and wid != ROOT:
            wid = self.windows[wid]['parent']
            out.append(wid)
        return out

    def set_focus(self, wid, revert):
        """the focus moves: FocusOut to the old window and, with NotifyVirtual, to its
        ancestors; FocusIn with NotifyVirtual to the new window's ancestors, then to the
        window itself, and with NotifyPointer to the pointer window below it. Xt turns
        the shell's FocusIn into keyboard focus for the widget under it, so a Motif text
        field only takes keys after these arrive."""
        old = self.focus_window()
        self.focus, self.focus_revert = wid, revert
        new = self.focus_window()
        if old == new:
            return
        NONLINEAR, VIRTUAL, POINTER, ANCESTOR, INFERIOR = 3, 1, 5, 0, 2
        old_anc = self.ancestors(old) if old in self.windows else []
        new_anc = self.ancestors(new) if new in self.windows else []
        common = next((a for a in old_anc if a == new or a in new_anc), ROOT)
        if old in self.windows:
            if self.is_ancestor(old, self.pointer_win) and self.pointer_win != old:
                self.focus_event(10, self.pointer_win, POINTER)
            self.focus_event(10, old, INFERIOR if old in new_anc else (ANCESTOR if new in old_anc else NONLINEAR))
            for a in old_anc:
                if a == common or a == new:
                    break
                self.focus_event(10, a, VIRTUAL)
        if new in self.windows:
            path = []
            for a in new_anc:
                if a == common or a == old:
                    break
                path.append(a)
            for a in reversed(path):
                self.focus_event(9, a, VIRTUAL)
            self.focus_event(9, new, INFERIOR if new in old_anc else (ANCESTOR if old in new_anc else NONLINEAR))
            if self.is_ancestor(new, self.pointer_win) and self.pointer_win != new:
                self.focus_event(9, self.pointer_win, POINTER)

    def key(self, keysym, down):
        """a key press or release of `keysym`, to the keyboard grab or the focus window"""
        code = keycode_for(keysym)
        if not code:
            return
        shift = keysym != KEYS[code - 8][0] and KEYS[code - 8][1] == keysym
        if keysym == 0xFFE1:
            self.modifiers = (self.modifiers | 1) if down else (self.modifiers & ~1)
        elif keysym == 0xFFE3:
            self.modifiers = (self.modifiers | 4) if down else (self.modifiers & ~4)
        elif keysym == 0xFFE9:
            self.modifiers = (self.modifiers | 8) if down else (self.modifiers & ~8)
        state = self.buttons | self.modifiers | (1 if shift else 0)
        ev, mask = (2, 1) if down else (3, 2)
        if self.kgrab:
            g = self.kgrab
            if g['owner_events']:
                w, cls = self.propagate(self.focus_start(), mask, ev, code, state, only_client=g['client'])
                if cls:
                    return
            self.input_event(g['client'], ev, code, g['window'], self.child_toward(g['window'], self.pointer_win), state)
            return
        self.propagate(self.focus_start(), mask, ev, code, state)

    def focus_start(self):
        f = self.focus_window()
        return self.pointer_win if self.is_ancestor(f, self.pointer_win) else f

    def type_text(self, text):
        for ch in text:
            if ch == '\n':
                ks = 0xFF0D
            elif ch == '\t':
                ks = 0xFF09
            elif ch == '\b':
                ks = 0xFF08
            else:
                ks = ord(ch)
            if ch.isalpha() and ch.isupper():
                self.key(0xFFE1, True)
                self.key(ks, True)
                self.key(ks, False)
                self.key(0xFFE1, False)
            else:
                self.key(ks, True)
                self.key(ks, False)

    def control(self, line):
        """one control-socket command -> one reply line"""
        parts = line.split()
        if not parts:
            return 'ok'
        cmd = parts[0]
        try:
            if cmd == 'move':
                self.move_pointer(int(parts[1]), int(parts[2]))
            elif cmd == 'mods':     # mods N: the modifier state (0x10 Mod2: Num Lock on, 2: Caps Lock)
                self.modifiers = int(parts[1], 0)
            elif cmd == 'press':
                self.press(int(parts[1]) if len(parts) > 1 else 1)
            elif cmd == 'release':
                self.release(int(parts[1]) if len(parts) > 1 else 1)
            elif cmd == 'click':
                self.move_pointer(int(parts[1]), int(parts[2]))
                b = int(parts[3]) if len(parts) > 3 else 1
                self.press(b)
                self.release(b)
            elif cmd == 'key':
                ks = KEYSYM_NAMES.get(parts[1], ord(parts[1]) if len(parts[1]) == 1 else 0)
                self.key(ks, True)
                self.key(ks, False)
            elif cmd == 'keydown' or cmd == 'keyup':
                ks = KEYSYM_NAMES.get(parts[1], ord(parts[1]) if len(parts[1]) == 1 else 0)
                self.key(ks, cmd == 'keydown')
            elif cmd == 'type':
                self.type_text(line.split(' ', 1)[1].encode().decode('unicode_escape'))
            elif cmd == 'snap':
                out, self.out = self.out, parts[1]
                self.dirty = True
                self.save()
                self.out = out
            elif cmd == 'windows':
                return 'ok ' + ' '.join(self.window_list())
            elif cmd == 'pointer':
                g = self.pgrab
                return 'ok %d %d %#x buttons=%#x grab=%s frozen=%d' % (self.px, self.py, self.pointer_win, self.buttons,
                                                                      'none' if g is None else '%#x/%s' % (g['window'], 'implicit' if g.get('implicit') else ('sync' if g['sync'] else 'async')),
                                                                      len(self.frozen))
            elif cmd == 'dump':     # dump WID FILE: a window's own image
                w = self.windows.get(int(parts[1], 16))
                if w is None or w.get('img') is None:
                    return 'error no image'
                w['img'].save(parts[2])
            elif cmd == 'why':      # why WID: how a window is composed
                wid = int(parts[1], 16)
                w = self.windows.get(wid)
                if w is None:
                    return 'error no window'
                return 'ok mapped=%s viewable=%s img=%s abs=%s parent=%#x' % (w['mapped'], self.viewable(wid),
                                                                              w['img'].size if w.get('img') is not None else None, self.abs_pos(wid), w['parent'])
            elif cmd == 'masks':    # masks WID: the event masks selected on a window and its ancestors, and grabs
                wid = int(parts[1], 16)
                out = []
                while wid in self.windows:
                    w = self.windows[wid]
                    out.append('%#x:%s' % (wid, ','.join('%#x' % m for m in w['masks'].values()) or '-'))
                    if wid == ROOT:
                        break
                    wid = w['parent']
                out.append('grabs:' + ','.join('%#x/b%d/m%#x/mask%#x/%s%s' % (g['window'], g['button'], g['modifiers'], g['mask'], 'own' if g['owner_events'] else 'grab', '/sync' if g['sync'] else '') for g in self.passive))
                return 'ok ' + ' '.join(out)
            elif cmd == 'focus':    # focus WID|pointerroot: as a window manager's SetInputFocus
                self.set_focus(1 if parts[1] == 'pointerroot' else int(parts[1], 16), 1)
            elif cmd == 'tree':
                return 'ok ' + ' '.join(self.tree_lines())
            elif cmd == 'requests':
                return 'ok ' + ' '.join('%s=%d' % kv for kv in sorted(self.counts.items()))
            elif cmd == 'quit':
                raise SystemExit(0)
            else:
                return 'error unknown command'
        except (IndexError, ValueError) as e:
            return 'error %s' % e
        return 'ok'

    def tree_lines(self, wid=ROOT, depth=0):
        w = self.windows.get(wid)
        if w is None:
            return []
        out = ['%s%#x:%dx%d+%d+%d%s%s%s' % ('.' * depth, wid, w['w'], w['h'], w['x'], w['y'], '' if w['mapped'] else ':unmapped',
                                           ':override' if w.get('override') else '',
                                           ':img' if w.get('img') is not None else (':inputonly' if w.get('inputonly') else ':bgpix%d' % w.get('bgpix', 0)))]
        for k, v in self.windows.items():
            if v['parent'] == wid:
                out += self.tree_lines(k, depth + 1)
        return out

    def window_list(self):
        """the viewable top-level windows (frames looked through): wid,WxH+x+y,class/name"""
        out = []
        for wid, w in self.windows.items():
            if wid == ROOT or not self.viewable(wid):
                continue
            cls = self.properties.get((wid, self.atoms.get('WM_CLASS', -1)))
            name = self.properties.get((wid, self.atoms.get('WM_NAME', -1)))
            if cls is None and name is None:
                continue
            label = (cls[2].split(b'\0')[1] if cls and cls[2].count(b'\0') >= 2 else (name[2] if name else b'?')).decode('latin1', 'replace')
            x, y = self.abs_pos(wid)
            out.append('%#x,%dx%d+%d+%d,%s' % (wid, w['w'], w['h'], x, y, label.replace(' ', '_')))
        return out

    def owner(self, w, c):
        """the client that created a window (its events go there), or c if that client has gone"""
        o = w.get('client')
        return o if o is not None and not o.closed else c

    def map_window(self, c, wid, expose=True):
        if wid not in self.windows:
            return
        w = self.windows[wid]
        was = w['mapped']
        w['mapped'] = True
        if self.draw and not was:
            self.resize_window_image(w)
            self.paint_background(w, 0, 0, w['w'], w['h'])
        self.dirty = True
        if not was:
            for cl in self.selectors(w, 0x20000) + self.selectors(self.windows.get(w['parent'], {}), 0x80000):
                cl.event(19, 0, struct.pack(cl.bo + 'IIB', wid, wid, w['override']))     # MapNotify
        if expose and self.viewable(wid):
            targets = self.selectors(w, 0x8000) or ([self.owner(w, c)] if not was else [])
            for cl in targets:
                if self.verbose:
                    sys.stderr.write('xstub:   -> Expose %#x %dx%d\n' % (wid, w['w'], w['h']))
                cl.event(12, 0, struct.pack(cl.bo + 'IHHHHH', wid, 0, 0, w['w'], w['h'], 0))
            for k, v in self.windows.items():
                if v['parent'] == wid and v['mapped']:
                    self.map_window(c, k)
        self.pointer_moved()

    def unmap_window(self, wid):
        w = self.windows.get(wid)
        if w is None or not w['mapped']:
            return
        w['mapped'] = False
        self.dirty = True
        for cl in self.selectors(w, 0x20000) + self.selectors(self.windows.get(w['parent'], {}), 0x80000):
            cl.event(18, 0, struct.pack(cl.bo + 'IIB', wid, wid, 0))     # UnmapNotify
        self.pointer_moved()

    def client_gone(self, c):
        """a closed connection's windows are destroyed, as a real server does (the
        window manager hears DestroyNotify and drops its frames)"""
        base = getattr(c, 'rid_base', None)
        if base is None:
            return
        mine = [k for k in self.windows if base <= k <= base | 0x1FFFFF]
        for k in mine:
            w = self.windows.get(k)
            if w is not None and not (base <= w['parent'] <= base | 0x1FFFFF):
                self.destroy_window(k)
        self.dirty = True

    def destroy_window(self, wid):
        w = self.windows.get(wid)
        if w is None or wid == ROOT:
            return
        for k in [k for k, v in self.windows.items() if v['parent'] == wid]:
            self.destroy_window(k)
        self.unmap_window(wid)
        for cl in self.selectors(w, 0x20000) + self.selectors(self.windows.get(w['parent'], {}), 0x80000):
            cl.event(17, 0, struct.pack(cl.bo + 'II', wid, wid))     # DestroyNotify
        del self.windows[wid]
        self.passive = [g for g in self.passive if g['window'] != wid]
        if self.pgrab and self.pgrab['window'] == wid:
            self.pgrab = None
        if self.focus == wid:
            self.focus = self.focus_revert if self.focus_revert in (0, 1) else ROOT
        self.properties = {k: v for k, v in self.properties.items() if k[0] != wid}

    def font_by_name(self, name):
        font = self.fontdir.open(name)
        if font is None and name.lower() in ('fixed', 'cursor', 'variable'):
            font = self.fontdir.open('6x13') or self.fontdir.open('-misc-fixed-*')
        return font

    def font_info(self, bo, font):
        """the fixed part of the QueryFont reply (after the 8-byte reply header)"""
        gl = font.glyphs.values() if font else []
        mn = struct.pack(bo + 'hhhhhH', min(g[0] for g in gl), min(g[1] for g in gl), min(g[2] for g in gl), min(g[3] for g in gl), min(g[4] for g in gl), 0) if gl else b'\0' * 12
        mx = struct.pack(bo + 'hhhhhH', max(g[0] for g in gl), max(g[1] for g in gl), max(g[2] for g in gl), max(g[3] for g in gl), max(g[4] for g in gl), 0) if gl else b'\0' * 12
        codes = sorted(font.glyphs) if font else [0]
        min_char, max_char = codes[0], codes[-1]
        min_b1, max_b1 = min_char >> 8, max_char >> 8
        min_b2 = min(c & 0xFF for c in codes)
        max_b2 = max(c & 0xFF for c in codes)
        nchars = (max_b1 - min_b1 + 1) * (max_b2 - min_b2 + 1)
        all_exist = 1 if nchars == len(codes) else 0
        # min_bounds(12) pad(4) max_bounds(12) pad(4) min_char_or_byte2(2) max_char_or_byte2(2) default_char(2) nprops(2) draw_dir(1) min_byte1 max_byte1 all_exist ascent(2) descent(2) nchars(4)
        return mn + b'\0' * 4 + mx + b'\0' * 4 + struct.pack(bo + 'HHHHBBBBhhI', min_b2, max_b2, font.default_char if font else 0, 0, 0, min_b1, max_b1, all_exist,
                                                            font.ascent if font else 0, font.descent if font else 0, nchars)

    def font_chars(self, bo, font):
        if not font:
            return b''
        codes = sorted(font.glyphs)
        min_b1, max_b1 = codes[0] >> 8, codes[-1] >> 8
        min_b2 = min(c & 0xFF for c in codes)
        max_b2 = max(c & 0xFF for c in codes)
        out = []
        for b1 in range(min_b1, max_b1 + 1):
            for b2 in range(min_b2, max_b2 + 1):
                g = font.glyphs.get((b1 << 8) | b2)
                if g:
                    out.append(struct.pack(bo + 'hhhhhH', g[0], g[1], g[2], g[3], g[4], 0))
                else:
                    out.append(b'\0' * 12)
        return b''.join(out)

    def poly(self, c, op, data, req):
        bo = c.bo
        d, g = struct.unpack(bo + 'II', req[4:12])
        gc = self.gc(g)
        img, dr, ox, oy = self.drawable(d)
        if not dr:
            return
        fg = self.rgb(gc['fg'])
        pts = req[12:]
        if op in (64, 65):   # PolyPoint, PolyLine
            n = len(pts) // 4
            coords = [struct.unpack(bo + 'hh', pts[4 * i:4 * i + 4]) for i in range(n)]
            if data == 1:    # previous-relative
                acc = []
                x = y = 0
                for px, py in coords:
                    x += px
                    y += py
                    acc.append((x, y))
                coords = acc
            coords = [(ox + x, oy + y) for x, y in coords]
            if op == 64:
                dr.point(coords, fill=fg)
            elif len(coords) > 1:
                dr.line(coords, fill=fg, width=max(1, gc.get('line_width', 0)))
        elif op == 66:       # PolySegment
            for i in range(len(pts) // 8):
                x1, y1, x2, y2 = struct.unpack(bo + 'hhhh', pts[8 * i:8 * i + 8])
                dr.line([(ox + x1, oy + y1), (ox + x2, oy + y2)], fill=fg, width=max(1, gc.get('line_width', 0)))
        elif op in (67, 70):  # PolyRectangle, PolyFillRectangle
            for i in range(len(pts) // 8):
                x, y, w, h = struct.unpack(bo + 'hhHH', pts[8 * i:8 * i + 8])
                if w and h:
                    if op == 70:
                        dr.rectangle([ox + x, oy + y, ox + x + w - 1, oy + y + h - 1], fill=fg)
                    else:
                        dr.rectangle([ox + x, oy + y, ox + x + w, oy + y + h], outline=fg)
        elif op in (68, 71):  # PolyArc, PolyFillArc
            for i in range(len(pts) // 12):
                x, y, w, h, a1, a2 = struct.unpack(bo + 'hhHHhh', pts[12 * i:12 * i + 12])
                if not w or not h:
                    continue
                start = -(a1 + a2) / 64.0
                end = -a1 / 64.0
                box = [ox + x, oy + y, ox + x + w, oy + y + h]
                if a2 >= 360 * 64 or a2 <= -360 * 64:
                    if op == 71:
                        dr.ellipse(box, fill=fg)
                    else:
                        dr.ellipse(box, outline=fg)
                elif op == 71:
                    dr.pieslice(box, start, end, fill=fg)
                else:
                    dr.arc(box, start, end, fill=fg)
        elif op == 69:       # FillPoly
            coords = [struct.unpack(bo + 'hh', pts[4 + 4 * i:8 + 4 * i]) for i in range((len(pts) - 4) // 4)]
            if req[12] == 1:  # previous-relative
                acc = []
                x = y = 0
                for px, py in coords:
                    x += px
                    y += py
                    acc.append((x, y))
                coords = acc
            coords = [(ox + x, oy + y) for x, y in coords]
            if len(coords) > 2:
                dr.polygon(coords, fill=fg)
        self.dirty = True

    def text(self, d, g, x, y, text, image=False, wide=False):
        """draw `text` (bytes; 2-byte characters when wide) with the GC's font at the
        baseline point (x, y); returns the advance"""
        gc = self.gc(g)
        img, dr, ox, oy = self.drawable(d)
        if not dr:
            return 0
        font = self.fonts.get(gc.get('font')) or self.font_by_name('fixed')
        fg, bg = self.rgb(gc['fg']), self.rgb(gc['bg'])
        if not font:
            s = text.decode('latin1')
            dr.text((ox + x, oy + y - FONT_ASCENT), s, font=self.pil_font, fill=fg)
            self.dirty = True
            return FONT_W * len(s)
        chars = [(text[i] << 8) | text[i + 1] for i in range(0, len(text) - 1, 2)] if wide else list(text)
        total = sum((font.glyphs.get(ch) or font.glyphs.get(font.default_char) or (0, 0, 0, 0, 0, []))[2] for ch in chars)
        if image:
            dr.rectangle([ox + x, oy + y - font.ascent, ox + x + total - 1, oy + y + font.descent - 1], fill=bg)
        px = img.load()
        W, H = img.size
        cx = x
        for ch in chars:
            gl = font.glyphs.get(ch) or font.glyphs.get(font.default_char)
            if not gl:
                continue
            l, r, w, a, dsc, rows = gl
            width = r - l
            for ry, v in enumerate(rows):
                yy = oy + y - a + ry
                if not 0 <= yy < H or not v:
                    continue
                for bx in range(width):
                    if v & (1 << (width - 1 - bx)):
                        xx = ox + cx + l + bx
                        if 0 <= xx < W:
                            px[xx, yy] = fg
            cx += w
        self.dirty = True
        return total

    def poly_text(self, c, op, req):
        bo = c.bo
        d, g = struct.unpack(bo + 'II', req[4:12])
        x, y = struct.unpack(bo + 'hh', req[12:16])
        items = req[16:]
        i = 0
        while i + 2 <= len(items):
            n = items[i]
            if n == 255:    # font shift: 4-byte font id, big-endian always
                fid = struct.unpack('>I', items[i + 1:i + 5])[0]
                self.gcs.setdefault(g, {'fg': 0, 'bg': 0xFFFFFF, 'font': 0, 'line_width': 0, 'fill_style': 0})['font'] = fid
                i += 5
                continue
            if n == 0 and i + 2 > len(items) - 1:
                break
            delta = struct.unpack('b', items[i + 1:i + 2])[0]
            size = n if op == 74 else 2 * n
            text = items[i + 2:i + 2 + size]
            x += delta
            if n:
                x += self.text(d, g, x, y, text, wide=(op == 75))
            i += 2 + size
            if n == 0 and size == 0 and delta == 0:
                break

    def put_image(self, c, fmt, req):
        bo = c.bo
        d, g = struct.unpack(bo + 'II', req[4:12])
        w, h, x, y = struct.unpack(bo + 'HHhh', req[12:20])
        left_pad, depth = req[20], req[21]
        data = req[24:]
        img, dr, ox, oy = self.drawable(d)
        if not img:
            return
        gc = self.gc(g)
        if fmt == 2 and depth == 24:       # ZPixmap
            stride = w * 4
            for py in range(h):
                row = data[py * stride:(py + 1) * stride]
                for px in range(min(w, len(row) // 4)):
                    v = struct.unpack('<I', row[4 * px:4 * px + 4])[0]     # the setup says LSBFirst images
                    img.putpixel((ox + x + px, oy + y + py), self.rgb(v))
        elif fmt == 2 and depth == 8:
            stride = (w + 3) & ~3
            for py in range(h):
                row = data[py * stride:py * stride + w]
                for px, v in enumerate(row):
                    img.putpixel((ox + x + px, oy + y + py), (v, v, v))
        else:                               # bitmap / XYPixmap depth 1: fg/bg
            stride = ((w + left_pad + 31) // 32) * 4
            fg, bg = self.rgb(gc['fg']), self.rgb(gc['bg'])
            for py in range(h):
                row = data[py * stride:(py + 1) * stride]
                for px in range(w):
                    bit = px + left_pad
                    byte = row[bit // 8] if bit // 8 < len(row) else 0
                    on = (byte >> (bit % 8)) & 1     # LSBFirst bit order as advertised
                    try:
                        img.putpixel((ox + x + px, oy + y + py), fg if on else bg)
                    except IndexError:
                        pass
        self.dirty = True

    def save(self):
        if self.fb and self.out and self.dirty:
            try:
                self.fb.paste(self.windows[ROOT]['img'], (0, 0))
                self.compose()
                self.fb.save(self.out)
            except OSError:
                pass
            self.dirty = False


def fnmatch(name, pattern):
    import fnmatch as fm
    return fm.fnmatchcase(name, pattern.replace('?', '?'))


def main(argv):
    display = 9
    out = 'xstub.png'
    timeout = None
    verbose = False
    width, height = 1024, 768
    root = None
    control = None
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == '-c':
            i += 1
            control = argv[i]
        elif a == '-r':
            i += 1
            root = argv[i]
        elif a == '-d':
            i += 1
            display = int(argv[i])
        elif a == '-o':
            i += 1
            out = argv[i]
        elif a == '-t':
            i += 1
            timeout = float(argv[i])
        elif a == '-v':
            verbose = True
        elif a == '--size':
            i += 1
            width, height = map(int, argv[i].split('x'))
        else:
            print(__doc__)
            return 2
        i += 1
    path = '/tmp/.X11-unix/X%d' % display
    os.makedirs('/tmp/.X11-unix', exist_ok=True)
    try:
        os.unlink(path)
    except OSError:
        pass
    ls = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    ls.bind(path)
    ls.listen(8)
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        # XSTUB_LISTEN=0.0.0.0 accepts clients that name the host by its LAN address
        # (a client that opens hostname:0.0)
        tcp.bind((os.environ.get('XSTUB_LISTEN', '127.0.0.1'), 6000 + display))
        tcp.listen(8)
    except OSError:
        tcp = None
    cs = None
    if control:
        try:
            os.unlink(control)
        except OSError:
            pass
        cs = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        cs.bind(control)
        cs.listen(4)
    ctl_conns = {}
    if root is None:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
        from hpuxemu import rootdir
        root = rootdir.default_root()
    fontdirs = [os.path.join(root, d) for d in ('usr/lib/X11/fonts/misc', 'usr/lib/X11/fonts/iso_8859.1/75dpi', 'usr/lib/X11/fonts/iso_8859.1/100dpi',
                                                 'usr/lib/X11/fonts/hp_roman8/75dpi', 'usr/dt/config/xfonts/C')]
    server = Server(width, height, out, verbose, [d for d in fontdirs if os.path.isdir(d)])
    sys.stderr.write('xstub: display :%d (%s), screen %dx%d, framebuffer -> %s\n' % (display, path, width, height, out))
    end = time.time() + timeout if timeout else None
    last_save = time.time()
    signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
    try:
        while True:
            if end and time.time() > end:
                break
            fds = [ls] + ([tcp] if tcp else []) + ([cs] if cs else []) + list(ctl_conns) + [c.sock for c in server.clients if not c.closed]
            r, _, _ = select.select(fds, [], [], 1.0)
            for s in r:
                if s is ls or s is tcp:
                    conn, _ = s.accept()
                    conn.settimeout(10.0)
                    server.clients.append(Client(conn, server))
                    continue
                if s is cs:
                    conn, _ = s.accept()
                    ctl_conns[conn] = b''
                    continue
                if s in ctl_conns:
                    try:
                        data = s.recv(4096)
                    except OSError:
                        data = b''
                    if not data:
                        del ctl_conns[s]
                        s.close()
                        continue
                    ctl_conns[s] += data
                    while b'\n' in ctl_conns[s]:
                        line, ctl_conns[s] = ctl_conns[s].split(b'\n', 1)
                        try:
                            answer = server.control(line.decode('utf-8', 'replace').strip())
                        except SystemExit:
                            raise
                        except Exception as e:
                            answer = 'error %s' % e
                        try:
                            s.sendall((answer + '\n').encode())
                        except OSError:
                            pass
                    continue
                for c in server.clients:
                    if c.sock is s:
                        try:
                            data = s.recv(65536)
                        except OSError:
                            data = b''
                        if not data:
                            c.closed = True
                            s.close()
                            server.client_gone(c)
                        else:
                            c.feed(data)
            server.clients = [c for c in server.clients if not c.closed]
            if time.time() - last_save > 1:
                server.save()
                last_save = time.time()
    finally:
        server.dirty = True
        server.save()
        try:
            os.unlink(path)
        except OSError:
            pass
        if control:
            try:
                os.unlink(control)
            except OSError:
                pass
        sys.stderr.write('xstub: requests: %s\n' % ', '.join('%s %d' % kv for kv in sorted(server.counts.items(), key=lambda kv: -kv[1])))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
